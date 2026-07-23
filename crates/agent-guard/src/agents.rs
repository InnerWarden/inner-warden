//! `innerwarden agents` - discover the AI coding agents on THIS machine and connect
//! the guardrail to them, instead of wiring each one by hand.
//!
//! Discovery combines independent evidence: `agent-guard`'s `/proc` scan finds
//! RUNNING agents by signature (Linux), a cross-platform `$PATH` check finds
//! available executables without launching them, and recognized configuration
//! files find configured agents even when idle. A bare dot-directory is only a
//! possible leftover, never proof of installation. Connecting = wiring the
//! Community guardrail by a reviewed, agent-specific mechanism. Claude Code
//! gets the fail-closed PreToolUse hook;
//! Cursor and Gemini use their JSON MCP configuration, and Codex uses TOML.
//! Other detected agents remain visible but are not modified automatically until
//! InnerWarden has an integration for their real configuration format.
//!
//! It is NOT Claude-Code-only. The decision logic (the known-agent table, merging
//! the two discovery sources, choosing connect targets) is pure and unit-tested;
//! only the `/proc` scan, the config-dir stat, and the file read/write are I/O.

/// The on-disk format of a recognized agent configuration file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    JsonObject,
    Json5Object,
    Toml,
    YamlMapping,
}

/// A profile-specific configuration convention, such as
/// `~/.openclaw-<profile>/openclaw.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileConfig {
    pub directory_prefix: &'static str,
    pub file_name: &'static str,
    pub format: ConfigFormat,
}

/// A known AI coding agent.
#[derive(Debug, PartialEq, Eq)]
pub struct Known {
    /// Canonical name.
    pub name: &'static str,
    /// Exact process/display aliases accepted by [`canonical`].
    pub aliases: &'static [&'static str],
    /// Exact executable basenames to look for on `$PATH` (never executed).
    pub executables: &'static [&'static str],
    /// The `$HOME`-relative path that may remain after an uninstall. Its mere
    /// presence is weak evidence and must not set `installed`.
    pub config_dir: &'static str,
    /// Recognized configuration files and their expected top-level format.
    pub config_files: &'static [(&'static str, ConfigFormat)],
    /// Optional bounded profile-directory convention.
    pub profile_config: Option<ProfileConfig>,
    /// Guarded via the native PreToolUse hook (Claude Code) rather than MCP.
    pub hookable: bool,
    /// The `$HOME`-relative `mcp.json` to route through the proxy, when the agent
    /// is guarded by wrapping MCP servers (JSON schema).
    pub mcp_json: Option<&'static str>,
    /// The `$HOME`-relative TOML config whose `[mcp_servers.*]` tables are wrapped
    /// (Codex uses `~/.codex/config.toml`, not an `mcp.json`).
    pub mcp_toml: Option<&'static str>,
}

pub const KNOWN: &[Known] = &[
    Known {
        name: "claude-code",
        aliases: &["claude", "claude-code", "claude code"],
        executables: &["claude", "claude-code"],
        config_dir: ".claude",
        config_files: &[(".claude/settings.json", ConfigFormat::JsonObject)],
        profile_config: None,
        hookable: true,
        mcp_json: None,
        mcp_toml: None,
    },
    Known {
        name: "cursor",
        aliases: &["cursor"],
        executables: &["cursor"],
        config_dir: ".cursor",
        config_files: &[(".cursor/mcp.json", ConfigFormat::JsonObject)],
        profile_config: None,
        hookable: false,
        mcp_json: Some(".cursor/mcp.json"),
        mcp_toml: None,
    },
    // Codex stores MCP servers in TOML (`~/.codex/config.toml` -> [mcp_servers.*]),
    // NOT an mcp.json.
    Known {
        name: "codex",
        aliases: &["codex", "codex-cli", "codex cli", "openai-codex"],
        executables: &["codex", "openai-codex"],
        config_dir: ".codex",
        config_files: &[(".codex/config.toml", ConfigFormat::Toml)],
        profile_config: None,
        hookable: false,
        mcp_json: None,
        mcp_toml: Some(".codex/config.toml"),
    },
    Known {
        name: "gemini",
        aliases: &["gemini", "gemini-cli", "gemini cli"],
        executables: &["gemini", "gemini-cli"],
        config_dir: ".gemini",
        config_files: &[(".gemini/settings.json", ConfigFormat::JsonObject)],
        profile_config: None,
        hookable: false,
        // Gemini CLI stores MCP servers in the top-level `mcpServers` key here.
        mcp_json: Some(".gemini/settings.json"),
        mcp_toml: None,
    },
    Known {
        name: "goose",
        aliases: &["goose"],
        executables: &["goose"],
        config_dir: ".config/goose",
        config_files: &[(".config/goose/config.yaml", ConfigFormat::YamlMapping)],
        profile_config: None,
        hookable: false,
        // Goose's supported user config is YAML, which the JSON proxy writer
        // must never rewrite as though it were an mcp.json file.
        mcp_json: None,
        mcp_toml: None,
    },
    Known {
        name: "aider",
        aliases: &["aider"],
        executables: &["aider"],
        config_dir: ".aider.conf.yml",
        config_files: &[(".aider.conf.yml", ConfigFormat::YamlMapping)],
        profile_config: None,
        hookable: false,
        // Aider has no reviewed native MCP integration.
        mcp_json: None,
        mcp_toml: None,
    },
    Known {
        name: "openclaw",
        aliases: &["openclaw", "moltbot", "clawdbot", "molty"],
        executables: &["openclaw"],
        config_dir: ".openclaw",
        config_files: &[(".openclaw/openclaw.json", ConfigFormat::Json5Object)],
        profile_config: Some(ProfileConfig {
            directory_prefix: ".openclaw-",
            file_name: "openclaw.json",
            format: ConfigFormat::Json5Object,
        }),
        hookable: false,
        // OpenClaw uses JSON5 with nested `mcp.servers`; leave it untouched
        // until that schema has its own lossless editor.
        mcp_json: None,
        mcp_toml: None,
    },
    Known {
        name: "hermes",
        aliases: &["hermes", "hermes-agent", "hermes agent", "hermes-acp"],
        executables: &["hermes", "hermes-agent", "hermes-acp"],
        config_dir: ".hermes",
        config_files: &[(".hermes/config.yaml", ConfigFormat::YamlMapping)],
        profile_config: None,
        hookable: false,
        // Hermes has a native hook surface, but it is fail-open on hook errors.
        // Keep it visible and manual until InnerWarden has a reviewed adapter.
        mcp_json: None,
        mcp_toml: None,
    },
];

/// Map a signature-detected process name (e.g. "claude", "Claude Code", "codex")
/// to a known agent. Only exact normalized aliases match: a process named
/// `openclaw-helper` or `my-codex` must not inherit a trusted identity. Pure.
pub fn canonical(detected_name: &str) -> Option<&'static Known> {
    fn normalized(name: &str) -> String {
        name.trim()
            .to_ascii_lowercase()
            .split([' ', '_', '-'])
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join("-")
    }

    let detected = normalized(detected_name);
    KNOWN.iter().find(|known| {
        detected == normalized(known.name)
            || known
                .aliases
                .iter()
                .any(|alias| detected == normalized(alias))
    })
}

/// Independent, non-authorizing signals that explain why an agent row exists.
/// These values are safe to expose in the local dashboard: they contain no PID,
/// absolute path, command line, prompt, or configuration content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryEvidence {
    ExecutableOnPath,
    Process,
    ConfigurationFile,
    CompatibleMcpConfiguration,
    PossibleLeftover,
}

impl DiscoveryEvidence {
    pub const fn api_name(self) -> &'static str {
        match self {
            Self::ExecutableOnPath => "executable_on_path",
            Self::Process => "process",
            Self::ConfigurationFile => "configuration_file",
            Self::CompatibleMcpConfiguration => "compatible_mcp_configuration",
            Self::PossibleLeftover => "possible_leftover",
        }
    }

    const fn order(self) -> u8 {
        match self {
            Self::ExecutableOnPath => 0,
            Self::Process => 1,
            Self::ConfigurationFile => 2,
            Self::CompatibleMcpConfiguration => 3,
            Self::PossibleLeftover => 4,
        }
    }
}

/// Static evidence collected for one known agent before it is merged with the
/// running-process scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownDiscovery {
    pub known: &'static Known,
    pub evidence: Vec<DiscoveryEvidence>,
}

/// One agent's merged discovery + guard status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentStatus {
    pub name: String,
    /// Running pids found by the process scan (empty when only found by config dir).
    pub pids: Vec<u32>,
    /// Backward-compatible installation flag. This is true only when an exact
    /// executable was found on `$PATH`; configuration and leftover markers are
    /// reported separately in `evidence`.
    pub installed: bool,
    /// Why this row was surfaced. Signals inform visibility only and never grant
    /// permission for automatic configuration changes.
    pub evidence: Vec<DiscoveryEvidence>,
    /// Guarded via the PreToolUse hook (vs MCP proxy).
    pub hookable: bool,
    /// The `$HOME`-relative `mcp.json` to wrap, when guarded via MCP JSON. `None`
    /// for a hook agent, a TOML agent, or a detected agent with no wiring path.
    pub mcp_json: Option<String>,
    /// The `$HOME`-relative TOML config to wrap (Codex's `config.toml`).
    pub mcp_toml: Option<String>,
    /// The guardrail is already wired for it.
    pub guarded: bool,
}

impl AgentStatus {
    /// Can we wire this agent (hook, an mcp.json, or a TOML config)?
    pub fn guardable(&self) -> bool {
        self.hookable || self.mcp_json.is_some() || self.mcp_toml.is_some()
    }

    pub fn has_evidence(&self, evidence: DiscoveryEvidence) -> bool {
        self.evidence.contains(&evidence)
    }

    fn add_evidence(&mut self, evidence: DiscoveryEvidence) {
        if evidence == DiscoveryEvidence::PossibleLeftover
            && self
                .evidence
                .iter()
                .any(|item| *item != DiscoveryEvidence::PossibleLeftover)
        {
            return;
        }
        if !self.evidence.contains(&evidence) {
            self.evidence.push(evidence);
        }
        if evidence != DiscoveryEvidence::PossibleLeftover {
            self.evidence
                .retain(|item| *item != DiscoveryEvidence::PossibleLeftover);
        }
        self.evidence.sort_by_key(|item| item.order());
        self.installed = self.has_evidence(DiscoveryEvidence::ExecutableOnPath);
    }
}

/// Legacy marker lookup retained for API compatibility. A returned item is only
/// a candidate with a known path; callers must not present it as installed
/// without executable/process/configuration evidence.
pub fn installed_agents(dir_exists: impl Fn(&str) -> bool) -> Vec<&'static Known> {
    KNOWN.iter().filter(|k| dir_exists(k.config_dir)).collect()
}

/// Merge process and filesystem/PATH discovery into one row per agent. A running
/// process with no `KNOWN` entry still gets a non-guardable row so it is not
/// hidden. Evidence does not make an integration reviewed or auto-connectable.
pub fn summarize_discovered(
    running: &[(String, u32)],
    discovered: &[KnownDiscovery],
    is_guarded: impl Fn(&str) -> bool,
) -> Vec<AgentStatus> {
    fn upsert_known(
        rows: &mut Vec<AgentStatus>,
        known: &Known,
        pid: Option<u32>,
        evidence: &[DiscoveryEvidence],
        guarded: bool,
    ) {
        if let Some(row) = rows.iter_mut().find(|row| row.name == known.name) {
            if let Some(p) = pid {
                if !row.pids.contains(&p) {
                    row.pids.push(p);
                }
            }
            for item in evidence {
                row.add_evidence(*item);
            }
        } else {
            let mut row = AgentStatus {
                name: known.name.to_string(),
                pids: pid.into_iter().collect(),
                installed: false,
                evidence: Vec::new(),
                hookable: known.hookable,
                mcp_json: known.mcp_json.map(String::from),
                mcp_toml: known.mcp_toml.map(String::from),
                guarded,
            };
            for item in evidence {
                row.add_evidence(*item);
            }
            rows.push(row);
        }
    }

    let mut rows: Vec<AgentStatus> = Vec::new();
    for (name, pid) in running {
        if let Some(known) = canonical(name) {
            upsert_known(
                &mut rows,
                known,
                Some(*pid),
                &[DiscoveryEvidence::Process],
                is_guarded(known.name),
            );
        } else {
            // Running but unknown to KNOWN: still surface it (no wiring path).
            if let Some(row) = rows.iter_mut().find(|r| r.name == *name) {
                if !row.pids.contains(pid) {
                    row.pids.push(*pid);
                }
                row.add_evidence(DiscoveryEvidence::Process);
            } else {
                rows.push(AgentStatus {
                    name: name.clone(),
                    pids: vec![*pid],
                    installed: false,
                    evidence: vec![DiscoveryEvidence::Process],
                    hookable: false,
                    mcp_json: None,
                    mcp_toml: None,
                    guarded: false,
                });
            }
        }
    }
    for discovery in discovered {
        upsert_known(
            &mut rows,
            discovery.known,
            None,
            &discovery.evidence,
            is_guarded(discovery.known.name),
        );
    }
    for row in &mut rows {
        row.pids.sort_unstable();
    }
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    rows
}

/// Backward-compatible pure merge for callers that already established an
/// installation through a stronger external probe. New discovery code should
/// call [`summarize_discovered`] with explicit evidence.
pub fn summarize(
    running: &[(String, u32)],
    installed: &[&'static Known],
    is_guarded: impl Fn(&str) -> bool,
) -> Vec<AgentStatus> {
    let discovered: Vec<_> = installed
        .iter()
        .map(|known| KnownDiscovery {
            known,
            evidence: vec![DiscoveryEvidence::ExecutableOnPath],
        })
        .collect();
    summarize_discovered(running, &discovered, is_guarded)
}

/// True when a `$HOME`-relative dotdir belongs to a KNOWN agent. Pure.
pub fn is_known_dir(dir: &str) -> bool {
    KNOWN.iter().any(|k| k.config_dir == dir)
}

/// From a list of discovered `~/.<x>/mcp.json`-style config dirs, return the ones
/// that are NOT a known agent - an UNRECOGNIZED agent-like config the user can
/// still connect manually. Pure/tested.
pub fn unrecognized_agents(config_dirs: &[String]) -> Vec<String> {
    let mut out: Vec<String> = config_dirs
        .iter()
        .filter(|d| !is_known_dir(d))
        .cloned()
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Choose which agents to connect for a `connect` request: `--all` (or no target)
/// = every GUARDABLE agent present (hook OR MCP); else the named one if guardable.
/// No longer hook-only - that was the Claude-Code-only bug. Pure/tested.
pub fn connect_targets<'a>(rows: &'a [AgentStatus], target: Option<&str>) -> Vec<&'a AgentStatus> {
    rows.iter()
        .filter(|r| r.guardable())
        .filter(|r| match target {
            Some(t) if t != "--all" => r.name.eq_ignore_ascii_case(t),
            _ => true,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_collapses_vendor_names() {
        assert_eq!(canonical("claude").map(|k| k.name), Some("claude-code"));
        assert_eq!(
            canonical("claude-code").map(|k| k.name),
            Some("claude-code")
        );
        assert_eq!(canonical("Cursor").map(|k| k.name), Some("cursor"));
        assert_eq!(canonical("Codex CLI").map(|k| k.name), Some("codex"));
        assert_eq!(canonical("gemini-cli").map(|k| k.name), Some("gemini"));
        assert_eq!(canonical("OpenClaw").map(|k| k.name), Some("openclaw"));
        assert_eq!(canonical("moltbot").map(|k| k.name), Some("openclaw"));
        assert_eq!(canonical("Hermes Agent").map(|k| k.name), Some("hermes"));
        assert!(canonical("bash").is_none());
    }

    #[test]
    fn canonical_never_trusts_substring_or_prefix_lookalikes() {
        for name in [
            "openclaw-helper",
            "openclaw-malware",
            "my-codex",
            "cursor-agent",
            "hermes-helper",
            "claude-impersonator",
        ] {
            assert!(canonical(name).is_none(), "lookalike matched: {name}");
        }
    }

    #[test]
    fn reviewed_agents_are_guardable_and_unreviewed_formats_stay_manual() {
        let guardable = |k: &Known| k.hookable || k.mcp_json.is_some() || k.mcp_toml.is_some();
        let guarded_names: Vec<_> = KNOWN
            .iter()
            .filter(|known| guardable(known))
            .map(|known| known.name)
            .collect();
        assert_eq!(
            guarded_names,
            vec!["claude-code", "cursor", "codex", "gemini"]
        );
        let cc = KNOWN.iter().find(|k| k.name == "claude-code").unwrap();
        assert!(cc.hookable && cc.mcp_json.is_none());
        let cursor = KNOWN.iter().find(|k| k.name == "cursor").unwrap();
        assert!(!cursor.hookable && cursor.mcp_json == Some(".cursor/mcp.json"));
        // Codex is wired via its TOML config (~/.codex/config.toml), not an mcp.json.
        let codex = KNOWN.iter().find(|k| k.name == "codex").unwrap();
        assert!(
            !codex.hookable
                && codex.mcp_json.is_none()
                && codex.mcp_toml == Some(".codex/config.toml"),
            "codex must be guarded via its TOML config"
        );
        let gemini = KNOWN.iter().find(|k| k.name == "gemini").unwrap();
        assert_eq!(gemini.mcp_json, Some(".gemini/settings.json"));
        for name in ["goose", "aider", "openclaw", "hermes"] {
            let known = KNOWN.iter().find(|known| known.name == name).unwrap();
            assert!(!guardable(known), "{name} must remain manual");
        }
    }

    #[test]
    fn installed_agents_from_dir_predicate() {
        let got = installed_agents(|d| d == ".claude" || d == ".cursor");
        let names: Vec<_> = got.iter().map(|k| k.name).collect();
        assert_eq!(names, vec!["claude-code", "cursor"]);
    }

    #[test]
    fn summarize_merges_running_and_installed_and_surfaces_unknown() {
        let running = vec![
            ("claude".to_string(), 100),
            ("claude-code".to_string(), 101),
            ("cursor".to_string(), 200),
            ("mystery-agent".to_string(), 300), // unknown -> still surfaced
        ];
        let installed = installed_agents(|d| d == ".claude" || d == ".codex");
        let rows = summarize(&running, &installed, |name| name == "claude-code");
        // claude-code, cursor, codex(installed), mystery-agent
        assert_eq!(rows.len(), 4);
        let cc = rows.iter().find(|r| r.name == "claude-code").unwrap();
        assert_eq!(cc.pids, vec![100, 101]);
        assert!(cc.installed && cc.guarded && cc.hookable);
        let cursor = rows.iter().find(|r| r.name == "cursor").unwrap();
        assert!(cursor.guardable() && cursor.mcp_json.as_deref() == Some(".cursor/mcp.json"));
        let codex = rows.iter().find(|r| r.name == "codex").unwrap();
        assert!(codex.installed && codex.pids.is_empty() && codex.guardable());
        let mystery = rows.iter().find(|r| r.name == "mystery-agent").unwrap();
        assert!(!mystery.guardable() && mystery.pids == vec![300]);
        assert!(mystery.has_evidence(DiscoveryEvidence::Process));
    }

    #[test]
    fn summarize_discovered_keeps_configuration_and_leftover_honest() {
        let openclaw = KNOWN.iter().find(|known| known.name == "openclaw").unwrap();
        let hermes = KNOWN.iter().find(|known| known.name == "hermes").unwrap();
        let rows = summarize_discovered(
            &[("OpenClaw".into(), 42)],
            &[
                KnownDiscovery {
                    known: openclaw,
                    evidence: vec![DiscoveryEvidence::PossibleLeftover],
                },
                KnownDiscovery {
                    known: hermes,
                    evidence: vec![DiscoveryEvidence::ConfigurationFile],
                },
            ],
            |_| false,
        );

        let openclaw = rows.iter().find(|row| row.name == "openclaw").unwrap();
        assert!(!openclaw.installed);
        assert_eq!(openclaw.evidence, vec![DiscoveryEvidence::Process]);
        let hermes = rows.iter().find(|row| row.name == "hermes").unwrap();
        assert!(
            !hermes.installed,
            "configuration is not executable evidence"
        );
        assert_eq!(hermes.evidence, vec![DiscoveryEvidence::ConfigurationFile]);
    }

    #[test]
    fn unrecognized_surfaces_unknown_agent_like_configs() {
        let dirs = vec![
            ".claude".to_string(),
            ".cursor".to_string(),
            ".myagent".to_string(),
            ".weirdcli".to_string(),
        ];
        assert_eq!(unrecognized_agents(&dirs), vec![".myagent", ".weirdcli"]);
        assert!(is_known_dir(".claude") && !is_known_dir(".myagent"));
    }

    #[test]
    fn connect_targets_covers_every_guardable_agent_not_just_hookable() {
        let rows = vec![
            AgentStatus {
                name: "claude-code".into(),
                pids: vec![],
                installed: true,
                evidence: vec![DiscoveryEvidence::ExecutableOnPath],
                hookable: true,
                mcp_json: None,
                mcp_toml: None,
                guarded: false,
            },
            AgentStatus {
                name: "cursor".into(),
                pids: vec![],
                installed: true,
                evidence: vec![DiscoveryEvidence::ExecutableOnPath],
                hookable: false,
                mcp_json: Some(".cursor/mcp.json".into()),
                mcp_toml: None,
                guarded: false,
            },
            AgentStatus {
                name: "mystery".into(),
                pids: vec![1],
                installed: false,
                evidence: vec![DiscoveryEvidence::Process],
                hookable: false,
                mcp_json: None,
                mcp_toml: None,
                guarded: false,
            },
        ];
        // --all now takes BOTH claude-code (hook) AND cursor (mcp), not just the hook one
        assert_eq!(connect_targets(&rows, None).len(), 2);
        assert_eq!(connect_targets(&rows, Some("cursor")).len(), 1);
        assert_eq!(connect_targets(&rows, Some("claude-code")).len(), 1);
        // the unguardable mystery agent is not a connect target
        assert!(connect_targets(&rows, Some("mystery")).is_empty());
    }
}
