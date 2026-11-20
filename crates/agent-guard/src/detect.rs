//! Auto-detection of AI agents running on the server.
//!
//! Scans the running processes (`/proc` on Linux, the kernel's process table
//! on macOS) to find those that match known agent signatures.
//! Also scans home directories for MCP config files to discover which
//! MCP servers are configured (and can be auto-wrapped).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use tracing::{info, warn};

use crate::signatures::{Signature, SignatureIndex};

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

/// Scan running processes for known AI agents: `/proc` on Linux, the
/// kernel's process table (libproc and `sysctl`) on macOS. Both match an
/// agent by the same rule ([`identify_process`]).
pub fn scan_processes(index: &SignatureIndex) -> Vec<DetectedAgent> {
    platform_scan(index)
}

/// Whether [`scan_processes`] can look at this host's processes at all. Where
/// it cannot, "no agent running" would be a claim nothing measured.
pub fn process_scan_can_look() -> bool {
    platform_scan_can_look()
}

#[cfg(not(target_os = "macos"))]
fn platform_scan(index: &SignatureIndex) -> Vec<DetectedAgent> {
    scan_processes_in_dir(index, Path::new("/proc"))
}

#[cfg(not(target_os = "macos"))]
fn platform_scan_can_look() -> bool {
    Path::new("/proc").is_dir()
}

#[cfg(target_os = "macos")]
fn platform_scan(index: &SignatureIndex) -> Vec<DetectedAgent> {
    match macos::process_table() {
        Some(table) => agents_in_table(index, table, macos::argv),
        None => {
            warn!("agent-guard: the process table could not be read, cannot scan processes");
            vec![]
        }
    }
}

#[cfg(target_os = "macos")]
fn platform_scan_can_look() -> bool {
    macos::list_pids().is_some()
}

/// The one rule every platform's scan matches an agent by. The process name
/// is enough for native binaries, but interpreter-launched agents (OpenClaw
/// is `node .../openclaw/dist/index.js`, its name "MainThread" on Linux,
/// "node" on macOS) only reveal their identity in the argv, which is read
/// only when the name does not match.
fn identify_process(
    index: &SignatureIndex,
    comm: &str,
    argv: impl FnOnce() -> Vec<String>,
) -> Option<&'static Signature> {
    index.identify(comm).or_else(|| {
        let argv = argv();
        let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        index.identify_cmdline(&argv_refs)
    })
}

/// Keep the first process seen for each agent.
fn note_agent(found: &mut HashMap<String, DetectedAgent>, sig: &Signature, pid: u32, comm: &str) {
    found
        .entry(sig.name.to_string())
        .or_insert_with(|| DetectedAgent {
            name: sig.name.to_string(),
            vendor: sig.vendor.to_string(),
            pid,
            comm: comm.to_string(),
            integration: format!("{:?}", sig.integration).to_lowercase(),
            mcp_configs: vec![],
        });
}

/// The agents found, by name, logged once.
fn finish_scan(found: HashMap<String, DetectedAgent>) -> Vec<DetectedAgent> {
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

/// The agents in a process table read some other way than `/proc` (the
/// macOS scan): (pid, process name) pairs, with `argv_of` reading a
/// process's argv when its name is not an agent's.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn agents_in_table(
    index: &SignatureIndex,
    table: Vec<(u32, String)>,
    argv_of: impl Fn(u32) -> Vec<String>,
) -> Vec<DetectedAgent> {
    let mut found: HashMap<String, DetectedAgent> = HashMap::new();
    for (pid, comm) in table {
        if let Some(sig) = identify_process(index, &comm, || argv_of(pid)) {
            note_agent(&mut found, sig, pid, &comm);
        }
    }
    finish_scan(found)
}

/// PURE: the argv in a macOS `KERN_PROCARGS2` buffer: `argc` as a native
/// int, the executable path and its NUL padding, then `argc` NUL-ended
/// arguments (the environment follows and is never read). Empty arguments
/// are dropped, as the `/proc` reader drops them.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_procargs2(buf: &[u8]) -> Vec<String> {
    let Some(head) = buf.get(..4) else {
        return Vec::new();
    };
    let argc = i32::from_ne_bytes([head[0], head[1], head[2], head[3]]);
    let Ok(argc) = usize::try_from(argc) else {
        return Vec::new();
    };
    let rest = &buf[4..];
    let Some(path_end) = rest.iter().position(|&b| b == 0) else {
        return Vec::new();
    };
    let args_start = rest[path_end..]
        .iter()
        .position(|&b| b != 0)
        .map_or(rest.len(), |offset| path_end + offset);
    rest[args_start..]
        .split(|&b| b == 0)
        .take(argc)
        .filter(|arg| !arg.is_empty())
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect()
}

/// The macOS process table, read from the kernel: no `/proc` there.
#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::{c_int, c_void};

    /// Every pid the kernel lists, or `None` when the list could not be read.
    pub(super) fn list_pids() -> Option<Vec<u32>> {
        // SAFETY: a null buffer asks only for the count.
        let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
        let count = usize::try_from(count).ok().filter(|n| *n > 0)?;
        // Room for processes started between the two calls.
        let capacity = count + 64;
        let mut pids: Vec<c_int> = vec![0; capacity];
        let bytes = c_int::try_from(capacity * std::mem::size_of::<c_int>()).ok()?;
        // SAFETY: the buffer holds `bytes` bytes and outlives the call.
        let got = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast::<c_void>(), bytes) };
        let got = usize::try_from(got).ok().filter(|n| *n > 0)?;
        pids.truncate(got.min(capacity));
        Some(
            pids.into_iter()
                .filter_map(|pid| u32::try_from(pid).ok().filter(|pid| *pid > 0))
                .collect(),
        )
    }

    /// A process's name, or `None` when it is gone or cannot be read.
    pub(super) fn name(pid: u32) -> Option<String> {
        let pid = c_int::try_from(pid).ok()?;
        let mut buf = [0u8; 256];
        // SAFETY: the buffer holds its length in bytes and outlives the call.
        let len =
            unsafe { libc::proc_name(pid, buf.as_mut_ptr().cast::<c_void>(), buf.len() as u32) };
        let len = usize::try_from(len).ok().filter(|n| *n > 0)?;
        Some(String::from_utf8_lossy(&buf[..len.min(buf.len())]).into_owned())
    }

    /// A process's argv, empty when it cannot be read (another user's
    /// process, or one that ended).
    pub(super) fn argv(pid: u32) -> Vec<String> {
        let Ok(pid) = c_int::try_from(pid) else {
            return Vec::new();
        };
        let Some(argmax) = argmax() else {
            return Vec::new();
        };
        let mut buf = vec![0u8; argmax];
        let mut size: libc::size_t = buf.len();
        let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
        // SAFETY: `size` is the buffer's length and both outlive the call.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                buf.as_mut_ptr().cast::<c_void>(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return Vec::new();
        }
        buf.truncate(size.min(buf.len()));
        super::parse_procargs2(&buf)
    }

    /// The kernel's limit on argv plus environment, the size of the buffer
    /// `KERN_PROCARGS2` fills.
    fn argmax() -> Option<usize> {
        let mut value: c_int = 0;
        let mut size: libc::size_t = std::mem::size_of::<c_int>();
        let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
        // SAFETY: `value` is a c_int and `size` says so.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                (&mut value as *mut c_int).cast::<c_void>(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return None;
        }
        usize::try_from(value).ok().filter(|n| *n > 0)
    }

    /// (pid, name) for every process whose name could be read.
    pub(super) fn process_table() -> Option<Vec<(u32, String)>> {
        let pids = list_pids()?;
        Some(
            pids.into_iter()
                .filter_map(|pid| name(pid).map(|name| (pid, name)))
                .collect(),
        )
    }
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

        if let Some(sig) = identify_process(index, &comm, || read_cmdline(&entry.path())) {
            note_agent(&mut found, sig, pid, &comm);
        }
    }

    finish_scan(found)
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

    /// The macOS scan matches by the same rule as `/proc`: the name, then the
    /// argv only when the name is not an agent's (node running OpenClaw).
    /// (NEW-20261119-macos-agent-process-scan-missing)
    #[test]
    fn a_process_table_is_matched_by_the_same_rule_as_proc() {
        let index = SignatureIndex::new();
        let table = vec![
            (10, "claude".to_string()),
            (11, "node".to_string()),
            (12, "zsh".to_string()),
            (13, "claude".to_string()),
        ];
        let argv_reads = std::cell::RefCell::new(Vec::new());
        let agents = agents_in_table(&index, table, |pid| {
            argv_reads.borrow_mut().push(pid);
            match pid {
                11 => vec![
                    "/opt/homebrew/bin/node".into(),
                    "/opt/homebrew/lib/node_modules/openclaw/dist/index.js".into(),
                    "gateway".into(),
                ],
                _ => vec!["/bin/zsh".into()],
            }
        });
        let names: Vec<(&str, u32)> = agents.iter().map(|a| (a.name.as_str(), a.pid)).collect();
        assert_eq!(names, vec![("Claude Code", 10), ("OpenClaw", 11)]);
        assert_eq!(
            *argv_reads.borrow(),
            vec![11, 12],
            "argv read only past a name"
        );
    }

    /// A `KERN_PROCARGS2` buffer: argc, the executable path with its NUL
    /// padding, the arguments, then the environment, which is never read.
    #[test]
    fn procargs2_gives_the_argv_and_never_the_environment() {
        let mut buf = 3i32.to_ne_bytes().to_vec();
        buf.extend_from_slice(b"/usr/local/bin/node\0\0\0\0");
        buf.extend_from_slice(b"node\0/x/openclaw/dist/index.js\0gateway\0");
        buf.extend_from_slice(b"HOME=/Users/a\0SECRET=s\0");
        assert_eq!(
            parse_procargs2(&buf),
            vec!["node", "/x/openclaw/dist/index.js", "gateway"]
        );
        assert!(parse_procargs2(&[]).is_empty());
        assert!(parse_procargs2(&(-1i32).to_ne_bytes()).is_empty());
        let mut no_path_end = 1i32.to_ne_bytes().to_vec();
        no_path_end.extend_from_slice(b"/bin/x");
        assert!(parse_procargs2(&no_path_end).is_empty());
    }

    /// On macOS the scan reads the kernel's process table: a program named
    /// like an agent is found by its pid, its name and its argv.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_macos_scan_finds_a_running_agent_by_name_and_argv() {
        assert!(process_scan_can_look());
        let dir = tempfile::tempdir().expect("tempdir");
        let fake = dir.path().join("claude");
        std::fs::copy("/bin/sleep", &fake).expect("copy sleep");
        let mut child = std::process::Command::new(&fake)
            .arg("30")
            .spawn()
            .expect("spawn");
        let pid = child.id();
        let table = macos::process_table().expect("process table");
        let argv = macos::argv(pid);
        let _ = child.kill();
        let _ = child.wait();
        let (_, name) = table
            .iter()
            .find(|(p, _)| *p == pid)
            .unwrap_or_else(|| panic!("pid {pid} not in the table"));
        assert_eq!(name, "claude");
        assert!(
            argv.first().is_some_and(|a| a.ends_with("/claude")),
            "{argv:?}"
        );
        assert_eq!(argv.get(1).map(String::as_str), Some("30"), "{argv:?}");
        let index = SignatureIndex::new();
        let found = agents_in_table(&index, vec![(pid, name.clone())], macos::argv);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "Claude Code");
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
