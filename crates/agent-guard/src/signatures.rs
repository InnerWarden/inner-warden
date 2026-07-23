//! AI agent and tool signatures for auto-detection.
//!
//! Distinction:
//! - **Agent**: autonomous, persistent memory, may run continuously (OpenClaw,
//!   ZeroClaw, Hermes Agent). `install_cmd` determines whether InnerWarden can
//!   install it; entries without one are detection-only/manual integrations.
//! - **Tool**: CLI/editor, no persistent memory, runs per-task (Claude Code, Aider)
//!   → auto-detected and monitored, not installed by us

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Kind {
    /// Autonomous agent with persistent memory; installation is optional per signature.
    Agent,
    /// CLI tool / coding assistant, auto-detected, monitored
    Tool,
    /// LLM runtime, auto-detected, API monitored
    Runtime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum IntegrationLevel {
    /// Tested, validated, full integration (MCP wrap, command validation)
    Official,
    /// eBPF monitoring only (process, file, network)
    Monitored,
}

pub struct Signature {
    pub name: &'static str,
    pub vendor: &'static str,
    pub kind: Kind,
    pub integration: IntegrationLevel,
    pub process_names: &'static [&'static str],
    pub install_cmd: Option<&'static str>,
}

pub static KNOWN: &[Signature] = &[
    // ═══════════════════════════════════════════════════════════
    // AGENTS, autonomous, persistent memory; some support `innerwarden agent add`
    // ═══════════════════════════════════════════════════════════
    Signature {
        name: "OpenClaw",
        vendor: "Peter Steinberger",
        kind: Kind::Agent,
        integration: IntegrationLevel::Official,
        process_names: &["openclaw", "moltbot", "clawdbot", "molty"],
        install_cmd: Some("npm install -g openclaw@latest"),
    },
    Signature {
        name: "ZeroClaw",
        vendor: "ZeroClaw Labs",
        kind: Kind::Agent,
        integration: IntegrationLevel::Official,
        process_names: &["zeroclaw", "zeroclaw-agent"],
        install_cmd: Some("cargo install zeroclaw"),
    },
    Signature {
        name: "Hermes Agent",
        vendor: "Nous Research",
        kind: Kind::Agent,
        // Detection is supported, but there is no reviewed Community adapter
        // that can honestly claim fail-closed enforcement yet.
        integration: IntegrationLevel::Monitored,
        process_names: &["hermes", "hermes-agent", "hermes-acp"],
        install_cmd: None,
    },
    // ═══════════════════════════════════════════════════════════
    // TOOLS, CLI / coding assistants, auto-detected
    // ═══════════════════════════════════════════════════════════
    Signature {
        name: "Claude Code",
        vendor: "Anthropic",
        kind: Kind::Tool,
        integration: IntegrationLevel::Official,
        process_names: &["claude", "claude-code"],
        install_cmd: None,
    },
    Signature {
        name: "Codex CLI",
        vendor: "OpenAI",
        kind: Kind::Tool,
        integration: IntegrationLevel::Official,
        process_names: &["codex", "openai-codex"],
        install_cmd: None,
    },
    Signature {
        name: "Gemini CLI",
        vendor: "Google",
        kind: Kind::Tool,
        integration: IntegrationLevel::Official,
        process_names: &["gemini", "gemini-cli"],
        install_cmd: None,
    },
    Signature {
        name: "Aider",
        vendor: "Aider-AI",
        kind: Kind::Tool,
        integration: IntegrationLevel::Official,
        process_names: &["aider"],
        install_cmd: None,
    },
    Signature {
        name: "Goose",
        vendor: "Block",
        kind: Kind::Tool,
        integration: IntegrationLevel::Official,
        process_names: &["goose"],
        install_cmd: None,
    },
    Signature {
        name: "Cursor",
        vendor: "Anysphere",
        kind: Kind::Tool,
        integration: IntegrationLevel::Official,
        process_names: &["cursor", "Cursor"],
        install_cmd: None,
    },
    Signature {
        name: "Windsurf",
        vendor: "Codeium",
        kind: Kind::Tool,
        integration: IntegrationLevel::Monitored,
        process_names: &["windsurf", "Windsurf"],
        install_cmd: None,
    },
    Signature {
        name: "Cline",
        vendor: "Community",
        kind: Kind::Tool,
        integration: IntegrationLevel::Monitored,
        process_names: &["cline"],
        install_cmd: None,
    },
    Signature {
        name: "GitHub Copilot",
        vendor: "GitHub",
        kind: Kind::Tool,
        integration: IntegrationLevel::Monitored,
        process_names: &["copilot-agent", "copilot", "copilot-language-server"],
        install_cmd: None,
    },
    Signature {
        name: "Devin",
        vendor: "Cognition",
        kind: Kind::Tool,
        integration: IntegrationLevel::Monitored,
        process_names: &["devin", "devin-agent"],
        install_cmd: None,
    },
    Signature {
        name: "OpenHands",
        vendor: "All Hands AI",
        kind: Kind::Tool,
        integration: IntegrationLevel::Monitored,
        process_names: &["openhands", "opendevin"],
        install_cmd: None,
    },
    Signature {
        name: "SWE-agent",
        vendor: "Princeton NLP",
        kind: Kind::Tool,
        integration: IntegrationLevel::Monitored,
        process_names: &["swe-agent", "sweagent"],
        install_cmd: None,
    },
    Signature {
        name: "AutoGPT",
        vendor: "Significant Gravitas",
        kind: Kind::Tool,
        integration: IntegrationLevel::Monitored,
        process_names: &["autogpt", "auto-gpt"],
        install_cmd: None,
    },
    Signature {
        name: "MetaGPT",
        vendor: "DeepWisdom",
        kind: Kind::Tool,
        integration: IntegrationLevel::Monitored,
        process_names: &["metagpt"],
        install_cmd: None,
    },
    // ═══════════════════════════════════════════════════════════
    // RUNTIMES, LLM servers, API monitored
    // ═══════════════════════════════════════════════════════════
    Signature {
        name: "Ollama",
        vendor: "Ollama",
        kind: Kind::Runtime,
        integration: IntegrationLevel::Monitored,
        process_names: &["ollama", "ollama_llama_server"],
        install_cmd: None,
    },
    Signature {
        name: "vLLM",
        vendor: "vLLM Project",
        kind: Kind::Runtime,
        integration: IntegrationLevel::Monitored,
        process_names: &["vllm", "vllm-server"],
        install_cmd: None,
    },
    Signature {
        name: "llama.cpp",
        vendor: "ggerganov",
        kind: Kind::Runtime,
        integration: IntegrationLevel::Monitored,
        process_names: &["llama-server", "llama-cli"],
        install_cmd: None,
    },
    Signature {
        name: "LM Studio",
        vendor: "LM Studio",
        kind: Kind::Runtime,
        integration: IntegrationLevel::Monitored,
        process_names: &["lm-studio", "lms"],
        install_cmd: None,
    },
];

#[derive(Debug)]
pub struct SignatureIndex {
    by_process: HashMap<String, usize>,
}

impl SignatureIndex {
    pub fn new() -> Self {
        let mut by_process = HashMap::new();
        for (i, sig) in KNOWN.iter().enumerate() {
            for name in sig.process_names {
                by_process.insert(name.to_lowercase(), i);
            }
        }
        Self { by_process }
    }

    pub fn identify(&self, process_name: &str) -> Option<&'static Signature> {
        let lower = process_name.to_lowercase();
        self.by_process.get(&lower).map(|idx| &KNOWN[*idx])
    }

    pub fn is_known(&self, process_name: &str) -> bool {
        self.identify(process_name).is_some()
    }

    /// Identify an agent from its full `argv` when `comm` did not match, the
    /// common case for interpreter-launched agents. OpenClaw runs as
    /// `node .../node_modules/openclaw/dist/index.js`, where `comm` is
    /// `node`/`MainThread` (node renames its main thread), so the identity
    /// lives only in the script path. Same for aider/goose/cline (python/node).
    ///
    /// Kept precise: this fires only when `argv[0]` is a known interpreter, and
    /// only matches a signature `process_name` that appears as an exact,
    /// `/`-delimited PATH COMPONENT of a later argv token. So `grep openclaw`
    /// (bare arg, no `/`) and `vim openclaw.md` (component is `openclaw.md`, not
    /// `openclaw`) do not false-positive.
    pub fn identify_cmdline(&self, argv: &[&str]) -> Option<&'static Signature> {
        let exe = basename(argv.first().copied().unwrap_or("")).to_lowercase();
        // Standalone-binary launch: argv[0] IS the agent's own native binary
        // (e.g. Claude Code, distributed as `~/.local/bin/claude` -> a native
        // executable, NOT an interpreter). Match the basename directly against a
        // known signature `process_name`. This is the tool-CLI counterpart of the
        // interpreter+script path below; it must run BEFORE the `is_interpreter`
        // gate, which would otherwise reject a non-interpreter argv[0] outright.
        if let Some(&idx) = self.by_process.get(&exe) {
            return Some(&KNOWN[idx]);
        }
        if !is_interpreter(&exe) {
            return None;
        }
        let mut prev = "";
        for token in argv.iter().skip(1) {
            // `python -m aider`: a bare module name right after `-m`.
            if prev == "-m" {
                if let Some(&idx) = self.by_process.get(&token.to_lowercase()) {
                    return Some(&KNOWN[idx]);
                }
            }
            // `node .../node_modules/openclaw/dist/index.js`: exact path component.
            if token.contains('/') {
                for component in token.split('/') {
                    if let Some(&idx) = self.by_process.get(&component.to_lowercase()) {
                        return Some(&KNOWN[idx]);
                    }
                }
            }
            prev = token;
        }
        None
    }

    /// True when `argv[0]`'s basename is itself a known agent `process_name`, a
    /// STANDALONE-BINARY launch (e.g. Claude Code's `~/.local/bin/claude`), as
    /// opposed to an interpreter+script launch (`node X.js`). The spec-081
    /// managed-agent verifier uses this to bind own-config to the agent user's
    /// HOME (derived from the binary path) rather than to a script install dir.
    pub fn is_standalone_binary_launch(&self, argv: &[&str]) -> bool {
        let exe = basename(argv.first().copied().unwrap_or("")).to_lowercase();
        self.by_process.contains_key(&exe)
    }

    /// Agents that can be installed via `innerwarden agent add`.
    pub fn installable_agents() -> Vec<&'static Signature> {
        KNOWN
            .iter()
            .filter(|s| s.kind == Kind::Agent && s.install_cmd.is_some())
            .collect()
    }
}

impl Default for SignatureIndex {
    fn default() -> Self {
        Self::new()
    }
}

/// Last `/`-delimited component of a path (the executable name).
fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// Script interpreters that launch agents as a child script, hiding the agent
/// identity from `comm`. Covers node/python/deno/bun/ruby/php/perl and
/// version-suffixed pythons (`python3.12`).
fn is_interpreter(exe: &str) -> bool {
    let python = exe.strip_prefix("python").is_some_and(|suffix| {
        suffix.is_empty()
            || (suffix.chars().any(|character| character.is_ascii_digit())
                && suffix
                    .chars()
                    .all(|character| character.is_ascii_digit() || character == '.'))
    });
    matches!(
        exe,
        "node" | "nodejs" | "deno" | "bun" | "ruby" | "php" | "perl" | "uv"
    ) || python
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_agents() {
        let idx = SignatureIndex::new();
        let oc = idx.identify("openclaw").unwrap();
        assert_eq!(oc.kind, Kind::Agent);
        let zc = idx.identify("zeroclaw").unwrap();
        assert_eq!(zc.kind, Kind::Agent);
        let hermes = idx.identify("hermes").unwrap();
        assert_eq!(hermes.name, "Hermes Agent");
        assert_eq!(hermes.integration, IntegrationLevel::Monitored);
    }

    #[test]
    fn process_identification_is_exact() {
        let idx = SignatureIndex::new();
        for lookalike in [
            "openclaw-helper",
            "openclaw-malware",
            "codex-wrapper",
            "hermes-helper",
            "claude-impersonator",
            "ollama-proxy",
        ] {
            assert!(idx.identify(lookalike).is_none(), "matched {lookalike}");
        }
    }

    #[test]
    fn identify_cmdline_detects_openclaw_launched_via_node() {
        // The exact live cmdline on the Azure VM (comm was "MainThread").
        let idx = SignatureIndex::new();
        let argv = [
            "/usr/bin/node",
            "/home/lab/.npm-global/lib/node_modules/openclaw/dist/index.js",
            "gateway",
            "--port",
            "18789",
        ];
        let sig = idx.identify_cmdline(&argv).expect("openclaw via node");
        assert_eq!(sig.name, "OpenClaw");
    }

    #[test]
    fn identify_cmdline_detects_python_agent() {
        let idx = SignatureIndex::new();
        let argv = [
            "/usr/bin/python3",
            "/usr/local/lib/python3.12/site-packages/aider/main.py",
        ];
        assert_eq!(idx.identify_cmdline(&argv).unwrap().name, "Aider");
    }

    #[test]
    fn identify_cmdline_detects_python_dash_m_module() {
        let idx = SignatureIndex::new();
        let argv = ["python3", "-m", "aider", "--model", "gpt-4o"];
        assert_eq!(idx.identify_cmdline(&argv).unwrap().name, "Aider");
        // A bare `aider` NOT preceded by -m must not match (could be any arg).
        assert!(idx.identify_cmdline(&["python3", "aider"]).is_none());
    }

    #[test]
    fn identify_cmdline_ignores_non_interpreter_and_bare_args() {
        let idx = SignatureIndex::new();
        // grep with a bare arg "openclaw" (no '/') → not an interpreter anyway.
        assert!(idx.identify_cmdline(&["grep", "openclaw"]).is_none());
        // node editing a doc whose component is "openclaw.md", not "openclaw".
        assert!(idx
            .identify_cmdline(&["/usr/bin/node", "/home/u/openclaw.md"])
            .is_none());
        // a plain node app with no agent in its path.
        assert!(idx
            .identify_cmdline(&["node", "/srv/app/server.js"])
            .is_none());
        // empty argv must not panic.
        assert!(idx.identify_cmdline(&[]).is_none());
        // Interpreter matching is exact enough that an arbitrary binary whose
        // name merely starts with `python` cannot unlock script-path matching.
        assert!(idx
            .identify_cmdline(&["python-helper", "/opt/openclaw/index.js"])
            .is_none());
    }

    #[test]
    fn identify_cmdline_detects_standalone_claude_code_binary() {
        // Claude Code 2.x ships as a native binary, launched directly (argv[0]
        // is the tool itself, NOT an interpreter). The real cmdline observed on a
        // host: `/home/lab/.local/bin/claude -p "..."`.
        let idx = SignatureIndex::new();
        let argv = ["/home/lab/.local/bin/claude", "-p", "say hi"];
        let sig = idx.identify_cmdline(&argv).expect("standalone claude");
        assert_eq!(sig.name, "Claude Code");
        // Bare command name (PATH-resolved) also matches.
        assert_eq!(
            idx.identify_cmdline(&["claude", "--version"]).unwrap().name,
            "Claude Code"
        );
        // The resolved native binary basename matches too.
        assert!(idx.is_standalone_binary_launch(&argv));
        assert!(idx.is_standalone_binary_launch(&["claude"]));
    }

    #[test]
    fn is_standalone_binary_launch_is_false_for_interpreter_and_unknown() {
        let idx = SignatureIndex::new();
        // node-launched OpenClaw: argv[0] is the interpreter, NOT a standalone
        // tool binary -> false (own-config binds to the script, not the home).
        assert!(!idx.is_standalone_binary_launch(&[
            "/usr/bin/node",
            "/home/lab/.npm-global/lib/node_modules/openclaw/dist/index.js",
        ]));
        // a random binary is not a known agent.
        assert!(!idx.is_standalone_binary_launch(&["/usr/bin/grep", "x"]));
        assert!(!idx.is_standalone_binary_launch(&[]));
    }

    #[test]
    fn identifies_tools() {
        let idx = SignatureIndex::new();
        let cc = idx.identify("claude").unwrap();
        assert_eq!(cc.kind, Kind::Tool);
    }

    #[test]
    fn identifies_runtimes() {
        let idx = SignatureIndex::new();
        let ol = idx.identify("ollama").unwrap();
        assert_eq!(ol.kind, Kind::Runtime);
    }

    #[test]
    fn installable_agents_exist() {
        let agents = SignatureIndex::installable_agents();
        assert!(agents.len() >= 2);
        assert!(agents.iter().any(|a| a.name == "OpenClaw"));
        assert!(agents.iter().any(|a| a.name == "ZeroClaw"));
        assert!(agents.iter().all(|agent| agent.name != "Hermes Agent"));
        let openclaw = agents
            .iter()
            .find(|agent| agent.name == "OpenClaw")
            .unwrap();
        assert_eq!(openclaw.install_cmd, Some("npm install -g openclaw@latest"));
    }

    #[test]
    fn unknown_not_found() {
        let idx = SignatureIndex::new();
        assert!(!idx.is_known("nginx"));
    }

    /// Pin the advertised signature count. Detection is by process `comm` only
    /// (no port/config-content fingerprinting), so the marketed number must
    /// match `KNOWN` exactly. If you add a signature, update any doc that
    /// quotes the count in the same change. (C1 audit: "25+ AI agents" was
    /// false; this test pins the exact current count.)
    #[test]
    fn known_signature_count_matches_advertised() {
        assert_eq!(KNOWN.len(), 21, "AI agent/tool/runtime signature count");
        let agents = KNOWN.iter().filter(|s| s.kind == Kind::Agent).count();
        let tools = KNOWN.iter().filter(|s| s.kind == Kind::Tool).count();
        let runtimes = KNOWN.iter().filter(|s| s.kind == Kind::Runtime).count();
        assert_eq!(
            (agents, tools, runtimes),
            (3, 14, 4),
            "signature kind breakdown"
        );
    }
}
