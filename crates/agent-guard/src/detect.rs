//! Auto-detection of AI agents running on the server.
//!
//! Scans /proc to find running processes that match known agent signatures.
//! Also scans home directories for MCP config files to discover which
//! MCP servers are configured (and can be auto-wrapped).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use tracing::{info, warn};

use crate::signatures::SignatureIndex;

/// A detected AI agent running on the server.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DetectedAgent {
    pub name: String,
    pub vendor: String,
    pub pid: u32,
    pub comm: String,
    pub integration: String,
    pub mcp_configs: Vec<PathBuf>,
}

/// Scan running processes for known AI agents.
pub fn scan_processes(index: &SignatureIndex) -> Vec<DetectedAgent> {
    scan_processes_in_dir(index, Path::new("/proc"))
}

/// Read `/proc/<pid>/cmdline` as a NUL-separated argv vector. Returns an empty
/// vec when the file is absent or unreadable (kernel threads, races, EPERM).
fn read_cmdline(proc_pid_dir: &Path) -> Vec<String> {
    match std::fs::read(proc_pid_dir.join("cmdline")) {
        Ok(bytes) => bytes
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn scan_processes_in_dir(index: &SignatureIndex, proc: &Path) -> Vec<DetectedAgent> {
    let mut found: HashMap<String, DetectedAgent> = HashMap::new();

    if !proc.exists() {
        warn!("agent-guard: /proc not available, cannot scan processes");
        return vec![];
    }

    let entries = match std::fs::read_dir(proc) {
        Ok(e) => e,
        Err(e) => {
            warn!(error = %e, "agent-guard: failed to read /proc");
            return vec![];
        }
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Only numeric dirs (PIDs)
        if !name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Read comm
        let comm_path = entry.path().join("comm");
        let comm = match std::fs::read_to_string(&comm_path) {
            Ok(c) => c.trim().to_string(),
            Err(_) => continue,
        };

        // `comm` is enough for native binaries, but interpreter-launched
        // agents (OpenClaw is `node .../openclaw/dist/index.js`, comm =
        // "MainThread") only reveal their identity in the cmdline. Fall back
        // to scanning argv when comm does not match.
        let sig = index.identify(&comm).or_else(|| {
            let argv = read_cmdline(&entry.path());
            let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
            index.identify_cmdline(&argv_refs)
        });

        if let Some(sig) = sig {
            let key = sig.name.to_string();
            found.entry(key).or_insert_with(|| DetectedAgent {
                name: sig.name.to_string(),
                vendor: sig.vendor.to_string(),
                pid,
                comm: comm.clone(),
                integration: format!("{:?}", sig.integration).to_lowercase(),
                mcp_configs: vec![],
            });
        }
    }

    let mut results: Vec<DetectedAgent> = found.into_values().collect();
    results.sort_by(|a, b| a.name.cmp(&b.name));

    if results.is_empty() {
        info!("agent-guard: no AI agents detected");
    } else {
        for agent in &results {
            info!(
                name = %agent.name,
                pid = agent.pid,
                integration = %agent.integration,
                "agent-guard: detected AI agent"
            );
        }
    }

    results
}

/// Scan for MCP config files in user home directories.
pub fn scan_mcp_configs() -> Vec<PathBuf> {
    scan_mcp_configs_in_roots(Path::new("/home"), Path::new("/root"))
}

fn scan_mcp_configs_in_roots(home_root: &Path, root_home: &Path) -> Vec<PathBuf> {
    let mut configs = vec![];

    // Reviewed JSON MCP locations. Do not invent an mcp.json path for agents
    // whose supported configuration is TOML, YAML, or JSON5.
    let patterns = [".cursor/mcp.json", ".gemini/settings.json"];

    // Scan /home/*/
    if let Ok(entries) = std::fs::read_dir(home_root) {
        for entry in entries.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            for pattern in &patterns {
                let path = entry.path().join(pattern);
                if path.exists() {
                    info!(path = %path.display(), "agent-guard: found MCP config");
                    configs.push(path);
                }
            }
        }
    }

    // Scan /root/
    for pattern in &patterns {
        let path = root_home.join(pattern);
        if path.exists() {
            info!(path = %path.display(), "agent-guard: found MCP config");
            configs.push(path);
        }
    }

    configs
}

/// Full detection: scan processes + MCP configs, match them together.
pub fn detect_all(index: &SignatureIndex) -> Vec<DetectedAgent> {
    detect_all_from_sources(
        index,
        Path::new("/proc"),
        Path::new("/home"),
        Path::new("/root"),
    )
}

fn detect_all_from_sources(
    index: &SignatureIndex,
    proc: &Path,
    home_root: &Path,
    root_home: &Path,
) -> Vec<DetectedAgent> {
    let mut agents = scan_processes_in_dir(index, proc);
    let configs = scan_mcp_configs_in_roots(home_root, root_home);
    associate_mcp_configs(&mut agents, &configs);

    let official = agents
        .iter()
        .filter(|a| a.integration == "official")
        .count();
    let monitored = agents.len() - official;

    info!(
        total = agents.len(),
        official,
        monitored,
        mcp_configs = configs.len(),
        "agent-guard: detection complete"
    );

    agents
}

fn associate_mcp_configs(agents: &mut [DetectedAgent], configs: &[PathBuf]) {
    for agent in agents.iter_mut() {
        // MCP configs are associated by presence in user home dirs
        for config in configs {
            let config_str = config.to_string_lossy().to_lowercase();
            let agent_lower = agent.name.to_lowercase();
            if config_str.contains(&agent_lower) {
                agent.mcp_configs.push(config.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_mcp_returns_vec() {
        // Just verify it doesn't panic
        let _configs = scan_mcp_configs();
    }

    #[test]
    fn detect_all_returns_vec() {
        let index = SignatureIndex::new();
        let _agents = detect_all(&index);
    }

    #[test]
    fn scan_processes_in_dir_detects_known_agents_and_deduplicates_by_name() {
        let temp = tempfile::tempdir().expect("tempdir");
        for (pid, comm) in [
            ("100", "claude\n"),
            ("101", "claude-code\n"),
            ("abc", "codex\n"),
        ] {
            let proc_dir = temp.path().join(pid);
            std::fs::create_dir(&proc_dir).expect("pid dir");
            std::fs::write(proc_dir.join("comm"), comm).expect("comm file");
        }
        std::fs::create_dir(temp.path().join("102")).expect("pid dir");
        std::fs::write(temp.path().join("102").join("comm"), "notepad\n").expect("comm file");

        let index = SignatureIndex::new();
        let agents = scan_processes_in_dir(&index, temp.path());

        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].name, "Claude Code");
        assert_eq!(agents[0].vendor, "Anthropic");
        assert_eq!(agents[0].integration, "official");
    }

    #[test]
    fn scan_processes_in_dir_detects_interpreter_launched_openclaw_via_cmdline() {
        // Regression: OpenClaw installed via npm runs as node, and node renames
        // its main thread, so /proc/<pid>/comm is "MainThread", comm matching
        // alone reported "No known agents detected" on a host running OpenClaw.
        let temp = tempfile::tempdir().expect("tempdir");
        let proc_dir = temp.path().join("12718");
        std::fs::create_dir(&proc_dir).expect("pid dir");
        std::fs::write(proc_dir.join("comm"), "MainThread\n").expect("comm");
        let argv = [
            "/usr/bin/node",
            "/home/lab/.npm-global/lib/node_modules/openclaw/dist/index.js",
            "gateway",
        ];
        std::fs::write(proc_dir.join("cmdline"), argv.join("\0")).expect("cmdline");

        let index = SignatureIndex::new();
        let agents = scan_processes_in_dir(&index, temp.path());

        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].name, "OpenClaw");
        assert_eq!(agents[0].comm, "MainThread");
    }

    #[test]
    fn scan_processes_in_dir_returns_empty_for_missing_or_unreadable_layouts() {
        let temp = tempfile::tempdir().expect("tempdir");
        let index = SignatureIndex::new();
        assert!(scan_processes_in_dir(&index, &temp.path().join("missing")).is_empty());

        std::fs::create_dir(temp.path().join("200")).expect("pid dir");
        assert!(scan_processes_in_dir(&index, temp.path()).is_empty());
    }

    #[test]
    fn scan_mcp_configs_in_roots_finds_user_and_root_configs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home_root = temp.path().join("home");
        let root_home = temp.path().join("root");
        let alice_cursor = home_root.join("alice/.cursor/mcp.json");
        let bob_gemini = home_root.join("bob/.gemini/settings.json");
        let root_cursor = root_home.join(".cursor/mcp.json");
        std::fs::create_dir_all(alice_cursor.parent().unwrap()).expect("alice dirs");
        std::fs::create_dir_all(bob_gemini.parent().unwrap()).expect("bob dirs");
        std::fs::create_dir_all(root_cursor.parent().unwrap()).expect("root dirs");
        std::fs::write(&alice_cursor, "{}").expect("alice config");
        std::fs::write(&bob_gemini, "{}").expect("bob config");
        std::fs::write(&root_cursor, "{}").expect("root config");

        let configs = scan_mcp_configs_in_roots(&home_root, &root_home);

        assert!(configs.contains(&alice_cursor));
        assert!(configs.contains(&bob_gemini));
        assert!(configs.contains(&root_cursor));
        assert_eq!(configs.len(), 3);
    }

    #[test]
    fn associate_mcp_configs_matches_agent_name_in_config_path() {
        let mut agents = vec![
            DetectedAgent {
                name: "Claude Code".into(),
                vendor: "Anthropic".into(),
                pid: 1,
                comm: "claude".into(),
                integration: "official".into(),
                mcp_configs: vec![],
            },
            DetectedAgent {
                name: "Codex CLI".into(),
                vendor: "OpenAI".into(),
                pid: 2,
                comm: "codex".into(),
                integration: "official".into(),
                mcp_configs: vec![],
            },
        ];
        let configs = vec![
            PathBuf::from("/home/alice/claude code/.mcp.json"),
            PathBuf::from("/home/alice/other/mcp.json"),
            PathBuf::from("/home/alice/codex cli/mcp.json"),
        ];

        associate_mcp_configs(&mut agents, &configs);

        assert_eq!(agents[0].mcp_configs, vec![configs[0].clone()]);
        assert_eq!(agents[1].mcp_configs, vec![configs[2].clone()]);
    }

    #[test]
    fn detect_all_from_sources_combines_process_and_mcp_config_scans() {
        let temp = tempfile::tempdir().expect("tempdir");
        let proc = temp.path().join("proc");
        let home_root = temp.path().join("home");
        let root_home = temp.path().join("root");
        let pid_dir = proc.join("300");
        let cursor_config = home_root.join("cursor/.cursor/mcp.json");
        std::fs::create_dir_all(&pid_dir).expect("pid dir");
        std::fs::write(pid_dir.join("comm"), "cursor\n").expect("comm file");
        std::fs::create_dir_all(cursor_config.parent().unwrap()).expect("config dir");
        std::fs::write(&cursor_config, "{}").expect("config");
        std::fs::create_dir_all(&root_home).expect("root home");

        let index = SignatureIndex::new();
        let agents = detect_all_from_sources(&index, &proc, &home_root, &root_home);

        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].name, "Cursor");
        assert_eq!(agents[0].mcp_configs, vec![cursor_config]);
    }
}
