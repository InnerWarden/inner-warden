//! Agent registry, tracks connected agents and their sessions.
//!
//! Agents connect via API or are discovered via `innerwarden agent scan`.
//! Each connected agent gets an ID, a session tracker, and a policy.
//! Multiple instances of the same agent type are supported.

use std::collections::HashMap;

use chrono::{DateTime, Utc};

use crate::session::SessionTracker;
use crate::signatures::{Kind, SignatureIndex};

/// Capture identity facts for a pid from `/proc/<pid>` at connect time (spec
/// 081 registry hardening). Returns `(exe_path, owner_uid, cmdline_fingerprint)`,
/// each `None` on any read failure. Best-effort: a failure here never blocks the
/// connect, the verifier simply has less to cross-check (and the live re-ID +
/// exe-root checks still stand). On non-Linux the `/proc` reads return None.
fn capture_proc_facts(pid: u32) -> (Option<String>, Option<u32>, Option<String>) {
    let base = format!("/proc/{pid}");

    let exe_path = std::fs::read_link(format!("{base}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());

    let owner_uid = std::fs::read_to_string(format!("{base}/status"))
        .ok()
        .and_then(|s| {
            for line in s.lines() {
                if let Some(rest) = line.strip_prefix("Uid:") {
                    return rest.split_whitespace().next().and_then(|v| v.parse().ok());
                }
            }
            None
        });

    let cmdline_fingerprint = std::fs::read(format!("{base}/cmdline")).ok().map(|bytes| {
        // interpreter|script-path, the two argv tokens that carry the identity
        // (e.g. `node|/home/lab/.npm-global/.../openclaw/dist/index.js`).
        let argv: Vec<String> = bytes
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();
        argv.into_iter().take(2).collect::<Vec<_>>().join("|")
    });

    (exe_path, owner_uid, cmdline_fingerprint)
}

/// A connected agent instance.
#[derive(Debug)]
pub struct ConnectedAgent {
    pub id: String,
    pub name: String,
    pub instance_label: String,
    pub pid: u32,
    pub kind: Kind,
    pub integration: String,
    pub connected_at: DateTime<Utc>,
    pub session: SessionTracker,
    pub policy: AgentPolicy,
    pub stats: AgentStats,
    // ── Spec 081 registry hardening ──────────────────────────────────────
    // Identity facts captured LIVE from `/proc/<pid>` at connect time so a
    // self-registered or pid-recycled process cannot inherit the managed-agent
    // response relaxation by holding a registry pid alone. The
    // `managed_agent_guard` verifier cross-checks the live process against these.
    /// `/proc/<pid>/exe` readlink target at connect. `None` when unreadable.
    pub exe_path: Option<String>,
    /// Owner uid of the process at connect (`/proc/<pid>/status` Uid:). `None`
    /// when unreadable.
    pub owner_uid: Option<u32>,
    /// Stable fingerprint of `/proc/<pid>/cmdline` at connect (interpreter +
    /// script path). `None` when unreadable.
    pub cmdline_fingerprint: Option<String>,
}

/// Policy applied to a connected agent.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentPolicy {
    /// warn = notify, guard = block dangerous, kill = block everything suspicious
    pub mode: String,
    /// Block access to sensitive paths (.ssh, .env, .aws)
    pub block_sensitive_paths: bool,
    /// Wrap MCP servers with inspection proxy
    pub wrap_mcp: bool,
    /// Max tool calls per minute (0 = unlimited)
    pub max_calls_per_minute: u32,
}

impl Default for AgentPolicy {
    fn default() -> Self {
        Self {
            mode: "warn".to_string(),
            block_sensitive_paths: true,
            wrap_mcp: true,
            max_calls_per_minute: 30,
        }
    }
}

/// Runtime stats for a connected agent.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct AgentStats {
    pub tool_calls: u64,
    pub blocked: u64,
    pub warnings: u64,
    pub files_accessed: u64,
}

/// The registry of all connected agents.
#[derive(Debug)]
pub struct Registry {
    agents: HashMap<String, ConnectedAgent>,
    index: SignatureIndex,
    /// Monotonic id counter, OWNED by this registry instance (not a global
    /// static): each `Registry` mints ids from its own space, so distinct
    /// instances, including parallel tests, never race on a shared counter.
    /// Seeded above the highest restored id in [`Registry::restore_from`].
    next_id: u64,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            agents: HashMap::new(),
            index: SignatureIndex::new(),
            next_id: 1,
        }
    }

    /// Connect an agent by PID. Returns the agent ID.
    ///
    /// Spec 081: captures identity facts (`exe_path`, `owner_uid`,
    /// `cmdline_fingerprint`) LIVE from `/proc/<pid>` so the managed-agent
    /// response relaxation cannot be inherited by a self-registered or
    /// pid-recycled process holding only the registry pid.
    pub fn connect(
        &mut self,
        name: &str,
        pid: u32,
        instance_label: Option<&str>,
    ) -> Result<String, String> {
        let (exe_path, owner_uid, cmdline_fingerprint) = capture_proc_facts(pid);
        self.connect_with_facts(
            name,
            pid,
            instance_label,
            exe_path,
            owner_uid,
            cmdline_fingerprint,
        )
    }

    /// Connect with explicitly-supplied identity facts. Used by `connect()`
    /// (which captures them live) and by tests (which inject them). Keeping the
    /// `/proc` read out of this function makes the registry insertion logic
    /// testable without a live process.
    pub fn connect_with_facts(
        &mut self,
        name: &str,
        pid: u32,
        instance_label: Option<&str>,
        exe_path: Option<String>,
        owner_uid: Option<u32>,
        cmdline_fingerprint: Option<String>,
    ) -> Result<String, String> {
        // Check if this PID is already connected
        if self.agents.values().any(|a| a.pid == pid) {
            return Err(format!("pid {pid} already connected"));
        }

        let id = format!("ag-{:04x}", self.next_id);
        self.next_id += 1;

        let (kind, integration) = if let Some(sig) = self.index.identify(name) {
            (sig.kind, format!("{:?}", sig.integration).to_lowercase())
        } else {
            (Kind::Tool, "monitored".to_string())
        };

        let label = instance_label
            .unwrap_or(&format!("{name}-{pid}"))
            .to_string();

        let agent = ConnectedAgent {
            id: id.clone(),
            name: name.to_string(),
            instance_label: label,
            pid,
            kind,
            integration,
            connected_at: Utc::now(),
            session: SessionTracker::new(),
            policy: AgentPolicy::default(),
            stats: AgentStats::default(),
            exe_path,
            owner_uid,
            cmdline_fingerprint,
        };

        tracing::info!(
            agent_id = %id,
            name = %agent.name,
            pid,
            label = %agent.instance_label,
            kind = ?kind,
            exe = agent.exe_path.as_deref().unwrap_or("?"),
            "agent connected"
        );

        self.agents.insert(id.clone(), agent);
        Ok(id)
    }

    /// Disconnect an agent by ID.
    pub fn disconnect(&mut self, agent_id: &str) -> bool {
        if let Some(agent) = self.agents.remove(agent_id) {
            tracing::info!(
                agent_id,
                name = %agent.name,
                pid = agent.pid,
                tool_calls = agent.stats.tool_calls,
                blocked = agent.stats.blocked,
                "agent disconnected"
            );
            true
        } else {
            false
        }
    }

    /// Get a connected agent by ID (mutable, for recording events).
    pub fn get_mut(&mut self, agent_id: &str) -> Option<&mut ConnectedAgent> {
        self.agents.get_mut(agent_id)
    }

    /// Get a connected agent by PID.
    pub fn by_pid(&self, pid: u32) -> Option<&ConnectedAgent> {
        self.agents.values().find(|a| a.pid == pid)
    }

    /// Get a connected agent by PID (mutable).
    pub fn by_pid_mut(&mut self, pid: u32) -> Option<&mut ConnectedAgent> {
        self.agents.values_mut().find(|a| a.pid == pid)
    }

    /// List all connected agents.
    pub fn list(&self) -> Vec<AgentSummary> {
        self.agents
            .values()
            .map(|a| AgentSummary {
                id: a.id.clone(),
                name: a.name.clone(),
                instance_label: a.instance_label.clone(),
                pid: a.pid,
                kind: format!("{:?}", a.kind).to_lowercase(),
                integration: a.integration.clone(),
                connected_at: a.connected_at,
                tool_calls: a.stats.tool_calls,
                blocked: a.stats.blocked,
                warnings: a.stats.warnings,
            })
            .collect()
    }

    /// Count connected agents by kind.
    pub fn count_agents(&self) -> usize {
        self.agents
            .values()
            .filter(|a| a.kind == Kind::Agent)
            .count()
    }

    pub fn count_tools(&self) -> usize {
        self.agents
            .values()
            .filter(|a| a.kind == Kind::Tool)
            .count()
    }

    pub fn count_total(&self) -> usize {
        self.agents.len()
    }

    // ---------------------------------------------------------------------
    // Persistence (2026-05-18)
    //
    // Pre-existing: the registry was in-memory only. Every restart of the
    // agent process, including the watchdog-driven binary swap shipped in
    // #681, wiped the ag-id assignments. The operator hit this twice in
    // the same hour after PRs #683 and #684 deployed: a known-good
    // OpenClaw at pid 1109 → ag-0001 binding vanished, the dashboard
    // returned `{"agents": [], "total": 0}`, and the operator would have
    // had to re-run `innerwarden agent connect` after every restart.
    //
    // Fix: snapshot the registry to a JSON file in the agent's data dir
    // after every connect/disconnect. Rehydrate on dashboard boot. The
    // tracked `session: SessionTracker` is per-process runtime state and
    // is reset to fresh on restore, only the durable identity (id, name,
    // pid, policy, stats) carries forward.
    // ---------------------------------------------------------------------

    /// Serialize the live agents to a snapshot suitable for `save_to`.
    /// Pure so the snapshot shape stays tested without touching disk.
    pub fn snapshot(&self) -> RegistrySnapshot {
        let agents = self
            .agents
            .values()
            .map(|a| PersistedAgent {
                id: a.id.clone(),
                name: a.name.clone(),
                instance_label: a.instance_label.clone(),
                pid: a.pid,
                kind: a.kind,
                integration: a.integration.clone(),
                connected_at: a.connected_at,
                policy: a.policy.clone(),
                stats: a.stats.clone(),
                exe_path: a.exe_path.clone(),
                owner_uid: a.owner_uid,
                cmdline_fingerprint: a.cmdline_fingerprint.clone(),
            })
            .collect();
        RegistrySnapshot {
            schema_version: 1,
            next_id: self.next_id,
            agents,
        }
    }

    /// Atomic save: write JSON to `<path>.tmp` then rename. Linux
    /// rename is atomic on the same filesystem, so a crash mid-write
    /// can never leave a half-written snapshot at `path`. Fail-soft:
    /// callers should log the error but not crash the agent.
    pub fn save_to(&self, path: &std::path::Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let body = serde_json::to_string_pretty(&self.snapshot())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, body)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Construct a registry from a previously-saved snapshot. This
    /// instance's `next_id` counter is seeded above the highest seen
    /// ag-id so future `connect` calls do not collide with restored
    /// ones. A missing file is NOT an error, a clean install / first
    /// boot simply starts empty. Corrupt JSON IS an error so the
    /// operator sees the problem instead of silently losing state.
    pub fn restore_from(path: &std::path::Path) -> std::io::Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let body = std::fs::read_to_string(path)?;
        let snapshot: RegistrySnapshot = serde_json::from_str(&body)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Seed next_id. Take the max of the persisted counter and
        // (max parsed ag-id + 1): the counter handles the case where
        // an agent was connected then disconnected (we lost the
        // disconnect but the counter remembers we burned the id), the
        // parsed-max handles snapshots from older code that didn't
        // persist next_id.
        let max_parsed = snapshot
            .agents
            .iter()
            .filter_map(|a| {
                a.id.strip_prefix("ag-")
                    .and_then(|hex| u64::from_str_radix(hex, 16).ok())
            })
            .max()
            .unwrap_or(0);
        let seed = snapshot.next_id.max(max_parsed + 1);

        let mut agents = HashMap::with_capacity(snapshot.agents.len());
        for p in snapshot.agents {
            agents.insert(
                p.id.clone(),
                ConnectedAgent {
                    id: p.id,
                    name: p.name,
                    instance_label: p.instance_label,
                    pid: p.pid,
                    kind: p.kind,
                    integration: p.integration,
                    connected_at: p.connected_at,
                    session: SessionTracker::new(),
                    policy: p.policy,
                    stats: p.stats,
                    exe_path: p.exe_path,
                    owner_uid: p.owner_uid,
                    cmdline_fingerprint: p.cmdline_fingerprint,
                },
            );
        }

        Ok(Self {
            agents,
            index: SignatureIndex::new(),
            next_id: seed,
        })
    }
}

/// Wire format for the persisted registry. Versioned so future
/// schema changes can branch on `schema_version`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RegistrySnapshot {
    pub schema_version: u32,
    pub next_id: u64,
    pub agents: Vec<PersistedAgent>,
}

/// One entry in the snapshot. Mirrors `ConnectedAgent` minus the
/// per-process runtime state (`SessionTracker`) which is reset on
/// restore.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistedAgent {
    pub id: String,
    pub name: String,
    pub instance_label: String,
    pub pid: u32,
    pub kind: Kind,
    pub integration: String,
    pub connected_at: DateTime<Utc>,
    pub policy: AgentPolicy,
    pub stats: AgentStats,
    // Spec 081 registry hardening, backward-compatible: a snapshot written by
    // pre-081 code simply omits these and they default to None on restore.
    #[serde(default)]
    pub exe_path: Option<String>,
    #[serde(default)]
    pub owner_uid: Option<u32>,
    #[serde(default)]
    pub cmdline_fingerprint: Option<String>,
}

// `AgentStats` needs `Deserialize` for the round-trip; the existing
// `serde::Serialize` derive on the struct definition does not include
// it, so we add a separate impl block here. Keeping the change scoped
// to this file (the field set is small and stable).
impl<'de> serde::Deserialize<'de> for AgentStats {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Mirror {
            #[serde(default)]
            tool_calls: u64,
            #[serde(default)]
            blocked: u64,
            #[serde(default)]
            warnings: u64,
            #[serde(default)]
            files_accessed: u64,
        }
        let m = Mirror::deserialize(deserializer)?;
        Ok(AgentStats {
            tool_calls: m.tool_calls,
            blocked: m.blocked,
            warnings: m.warnings,
            files_accessed: m.files_accessed,
        })
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary for API/CLI output.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AgentSummary {
    pub id: String,
    pub name: String,
    pub instance_label: String,
    pub pid: u32,
    pub kind: String,
    pub integration: String,
    pub connected_at: DateTime<Utc>,
    pub tool_calls: u64,
    pub blocked: u64,
    pub warnings: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_and_list() {
        let mut reg = Registry::new();
        let id = reg.connect("openclaw", 1234, Some("work-agent")).unwrap();
        assert!(id.starts_with("ag-"));

        let list = reg.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "openclaw");
        assert_eq!(list[0].instance_label, "work-agent");
        assert_eq!(list[0].kind, "agent");
    }

    #[test]
    fn multiple_instances_same_agent() {
        let mut reg = Registry::new();
        let id1 = reg.connect("openclaw", 1000, Some("personal")).unwrap();
        let id2 = reg.connect("openclaw", 2000, Some("work")).unwrap();
        assert_ne!(id1, id2);
        assert_eq!(reg.count_agents(), 2);
    }

    #[test]
    fn reject_duplicate_pid() {
        let mut reg = Registry::new();
        reg.connect("openclaw", 1234, None).unwrap();
        assert!(reg.connect("zeroclaw", 1234, None).is_err());
    }

    #[test]
    fn disconnect() {
        let mut reg = Registry::new();
        let id = reg.connect("openclaw", 1234, None).unwrap();
        assert_eq!(reg.count_total(), 1);
        assert!(reg.disconnect(&id));
        assert_eq!(reg.count_total(), 0);
    }

    #[test]
    fn by_pid() {
        let mut reg = Registry::new();
        reg.connect("openclaw", 1234, None).unwrap();
        assert!(reg.by_pid(1234).is_some());
        assert!(reg.by_pid(9999).is_none());
    }

    #[test]
    fn unknown_agent_connects_as_tool() {
        let mut reg = Registry::new();
        reg.connect("my-custom-agent", 5555, None).unwrap();
        let list = reg.list();
        assert_eq!(list[0].kind, "tool");
        assert_eq!(list[0].integration, "monitored");
    }

    #[test]
    fn mixed_agents_and_tools() {
        let mut reg = Registry::new();
        reg.connect("openclaw", 1000, None).unwrap();
        reg.connect("claude", 2000, None).unwrap();
        reg.connect("ollama", 3000, None).unwrap();
        assert_eq!(reg.count_agents(), 1); // only openclaw
        assert_eq!(reg.count_tools(), 1); // claude
        assert_eq!(reg.count_total(), 3);
    }

    // -----------------------------------------------------------------
    // Persistence (2026-05-18), regression anchors for the agent-guard
    // registry losing all state on every agent restart. Operator saw
    // {"agents": [], "total": 0} from /api/agent-guard/agents
    // immediately after the watchdog dance from PRs #683/#684 swapped
    // the agent binary. Without these tests the in-memory-only
    // behaviour could regress invisibly.
    // -----------------------------------------------------------------

    fn unique_pid() -> u32 {
        // Randomise pids across persistence tests to avoid collisions with
        // sibling tests in the same module (registry insists pids be unique).
        // Using `std::process::id() ^ time_nanos` keeps the pid unique
        // per test invocation without pulling in a random crate.
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        (std::process::id() ^ t) & 0x7fff_ffff
    }

    #[test]
    fn snapshot_round_trips_through_save_to_and_restore_from() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("registry.json");
        let pid = unique_pid();

        let mut reg = Registry::new();
        let id = reg.connect("openclaw", pid, Some("prod")).unwrap();
        // Tweak stats so we can prove they round-trip too.
        let agent = reg.get_mut(&id).unwrap();
        agent.stats.tool_calls = 17;
        agent.stats.blocked = 3;
        agent.policy.mode = "guard".to_string();
        agent.policy.max_calls_per_minute = 60;

        reg.save_to(&path).expect("save_to");

        let restored = Registry::restore_from(&path).expect("restore_from");
        let listed = restored.list();
        assert_eq!(listed.len(), 1);
        let entry = &listed[0];
        assert_eq!(entry.id, id);
        assert_eq!(entry.name, "openclaw");
        assert_eq!(entry.instance_label, "prod");
        assert_eq!(entry.pid, pid);
        assert_eq!(entry.kind, "agent");
        assert_eq!(entry.integration, "official");
        assert_eq!(entry.tool_calls, 17);
        assert_eq!(entry.blocked, 3);
        // Policy is not on AgentSummary; reach into the registry directly.
        let agent = restored.by_pid(pid).expect("restored agent by pid");
        assert_eq!(agent.policy.mode, "guard");
        assert_eq!(agent.policy.max_calls_per_minute, 60);
    }

    #[test]
    fn restore_from_missing_file_returns_empty_registry() {
        // Clean-install / first-boot case. Must not be an error.
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("does-not-exist.json");
        let reg = Registry::restore_from(&path).expect("missing file ok");
        assert_eq!(reg.count_total(), 0);
    }

    #[test]
    fn restore_from_corrupt_json_returns_invalid_data_error() {
        // Don't silently lose state, surface the corruption so the
        // operator sees it.
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("corrupt.json");
        std::fs::write(&path, "this is not json {{ broken").unwrap();
        let err = Registry::restore_from(&path).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn restore_seeds_next_id_above_restored_ids_so_future_connects_dont_collide() {
        // The exact failure this guards against: snapshot has ag-0001,
        // we restart, next_id resets to 1, next connect tries to mint
        // ag-0001 again and overwrites the restored agent. The counter is
        // per-instance, so this is deterministic under parallel tests.
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("registry.json");
        let pid_a = unique_pid();
        let pid_b = unique_pid().wrapping_add(1);

        // Pre-write a snapshot with a high-numbered id but a low
        // next_id, exercises the "parse max id + 1" branch.
        let snapshot = RegistrySnapshot {
            schema_version: 1,
            next_id: 1,
            agents: vec![PersistedAgent {
                id: "ag-0042".to_string(),
                name: "openclaw".to_string(),
                instance_label: "test".to_string(),
                pid: pid_a,
                kind: Kind::Agent,
                integration: "official".to_string(),
                connected_at: chrono::Utc::now(),
                policy: AgentPolicy::default(),
                stats: AgentStats::default(),
                exe_path: None,
                owner_uid: None,
                cmdline_fingerprint: None,
            }],
        };
        std::fs::write(&path, serde_json::to_string(&snapshot).unwrap()).unwrap();

        let mut reg = Registry::restore_from(&path).expect("restore_from");
        // Existing agent restored.
        assert!(reg.by_pid(pid_a).is_some());

        // New connect must NOT reuse ag-0042.
        let new_id = reg.connect("claude", pid_b, None).unwrap();
        assert_ne!(new_id, "ag-0042");
        // Must be strictly above 0x42 = 66.
        let parsed = u64::from_str_radix(new_id.trim_start_matches("ag-"), 16).unwrap();
        assert!(
            parsed > 0x42,
            "new id {new_id} should be > ag-0042 to avoid collision"
        );
    }

    // -----------------------------------------------------------------
    // Spec 081 registry hardening, exe_path / owner_uid /
    // cmdline_fingerprint round-trip + backward-compat.
    // -----------------------------------------------------------------

    #[test]
    fn connect_with_facts_stores_identity_facts() {
        let mut reg = Registry::new();
        let id = reg
            .connect_with_facts(
                "OpenClaw",
                unique_pid(),
                Some("prod"),
                Some("/home/lab/.npm-global/lib/node_modules/openclaw/dist/index.js".to_string()),
                Some(1000),
                Some(
                    "node|/home/lab/.npm-global/lib/node_modules/openclaw/dist/index.js"
                        .to_string(),
                ),
            )
            .unwrap();
        let agent = reg.get_mut(&id).unwrap();
        assert_eq!(agent.owner_uid, Some(1000));
        assert!(agent
            .exe_path
            .as_deref()
            .unwrap()
            .contains("node_modules/openclaw"));
        assert!(agent
            .cmdline_fingerprint
            .as_deref()
            .unwrap()
            .starts_with("node|"));
    }

    #[test]
    fn hardening_facts_round_trip_through_snapshot() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("registry.json");
        let pid = unique_pid();
        let mut reg = Registry::new();
        reg.connect_with_facts(
            "OpenClaw",
            pid,
            Some("prod"),
            Some("/home/lab/.npm-global/lib/node_modules/openclaw/dist/index.js".to_string()),
            Some(1000),
            Some("node|/home/lab/x".to_string()),
        )
        .unwrap();
        reg.save_to(&path).unwrap();

        let restored = Registry::restore_from(&path).unwrap();
        let agent = restored.by_pid(pid).expect("restored");
        assert_eq!(agent.owner_uid, Some(1000));
        assert_eq!(
            agent.exe_path.as_deref(),
            Some("/home/lab/.npm-global/lib/node_modules/openclaw/dist/index.js")
        );
        assert_eq!(
            agent.cmdline_fingerprint.as_deref(),
            Some("node|/home/lab/x")
        );
    }

    #[test]
    fn pre_081_snapshot_without_hardening_fields_restores_with_none() {
        // Backward-compat: a snapshot written before spec 081 has no
        // exe_path/owner_uid/cmdline_fingerprint keys. `#[serde(default)]`
        // must default them to None instead of failing the restore.
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("registry.json");
        let pid = unique_pid();
        let legacy = format!(
            r#"{{
              "schema_version": 1,
              "next_id": 2,
              "agents": [{{
                "id": "ag-0001",
                "name": "openclaw",
                "instance_label": "legacy",
                "pid": {pid},
                "kind": "Agent",
                "integration": "official",
                "connected_at": "2026-05-18T00:00:00Z",
                "policy": {{"mode":"warn","block_sensitive_paths":true,"wrap_mcp":true,"max_calls_per_minute":30}},
                "stats": {{"tool_calls":0,"blocked":0,"warnings":0,"files_accessed":0}}
              }}]
            }}"#
        );
        std::fs::write(&path, legacy).unwrap();
        let restored = Registry::restore_from(&path).expect("legacy snapshot must restore");
        let agent = restored.by_pid(pid).expect("restored legacy agent");
        assert_eq!(agent.exe_path, None);
        assert_eq!(agent.owner_uid, None);
        assert_eq!(agent.cmdline_fingerprint, None);
    }

    // -----------------------------------------------------------------
    // Spec 081 registry hardening, LIVE `/proc` capture path
    // (`capture_proc_facts` + `connect`). These hit the real `/proc` of the
    // running test process so the capture branch is covered on Linux CI; on
    // non-Linux the reads return None and we assert that fail-soft shape.
    // -----------------------------------------------------------------

    #[test]
    fn capture_proc_facts_reads_own_process() {
        let (exe_path, owner_uid, cmdline_fingerprint) = capture_proc_facts(std::process::id());
        if cfg!(target_os = "linux") {
            assert!(
                exe_path.is_some(),
                "own /proc/self/exe must readlink on Linux"
            );
            assert!(
                owner_uid.is_some(),
                "own /proc/self/status Uid must parse on Linux"
            );
            let fp = cmdline_fingerprint.expect("own /proc/self/cmdline must read on Linux");
            assert!(
                !fp.is_empty(),
                "fingerprint (first-2-argv joined by |) must be non-empty"
            );
        } else {
            // No /proc → best-effort capture yields all-None (connect still works).
            assert!(exe_path.is_none());
            assert!(owner_uid.is_none());
            assert!(cmdline_fingerprint.is_none());
        }
    }

    #[test]
    fn capture_proc_facts_missing_pid_is_all_none() {
        // A pid that does not exist → every /proc read fails → all None. This
        // is the fail-soft branch that keeps connect() working even when the
        // live capture cannot read anything.
        let (exe_path, owner_uid, cmdline_fingerprint) = capture_proc_facts(u32::MAX);
        assert!(exe_path.is_none());
        assert!(owner_uid.is_none());
        assert!(cmdline_fingerprint.is_none());
    }

    #[test]
    fn connect_captures_live_proc_facts_for_own_pid() {
        // `connect` (as opposed to `connect_with_facts`) runs the live
        // `capture_proc_facts` against the supplied pid. Using the test
        // process's own pid means the capture succeeds on Linux and the stored
        // ConnectedAgent carries the identity facts.
        let mut reg = Registry::new();
        let pid = std::process::id();
        let id = reg
            .connect("OpenClaw", pid, None)
            .expect("connect with live capture");
        let agent = reg.by_pid(pid).expect("stored agent");
        assert_eq!(agent.id, id);
        if cfg!(target_os = "linux") {
            assert!(
                agent.exe_path.is_some(),
                "connect() must capture /proc/self/exe on Linux"
            );
            assert!(
                agent.owner_uid.is_some(),
                "connect() must capture owner uid on Linux"
            );
            assert!(
                agent
                    .cmdline_fingerprint
                    .as_deref()
                    .map(|f| !f.is_empty())
                    .unwrap_or(false),
                "connect() must capture a non-empty cmdline fingerprint on Linux"
            );
        }
    }

    #[test]
    fn save_to_is_atomic_via_rename() {
        // The .tmp side-file must not linger after a successful save,
        // an orphaned .tmp would mean we crashed mid-rename, which
        // never happens on a clean save.
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("registry.json");
        let mut reg = Registry::new();
        reg.connect("openclaw", unique_pid(), None).unwrap();
        reg.save_to(&path).expect("save");
        assert!(path.exists());
        assert!(
            !path.with_extension("json.tmp").exists(),
            "tmp file must be renamed away on success"
        );
    }
}
