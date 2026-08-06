//! Which agents this host runs, and how the guardrail can get in front of each.
//!
//! # Why
//!
//! `install` accepted exactly one value, `claude-code`, and refused everything
//! else with "only 'claude-code' is supported today". The product's claim is that
//! it protects whatever agent the user runs, so that refusal read as "InnerWarden
//! cannot protect this", which is mostly false: `agents connect` already rewrites
//! a supported agent's MCP configuration to run through the proxy, and `contain`
//! covers the rest.
//!
//! The refusal also hid the real shape of the problem. Not every agent HAS
//! somewhere to hang a hook, so the honest answer is per agent, not one blanket
//! yes or no.
//!
//! # The mechanisms are not interchangeable
//!
//! * [`Mechanism::SettingsHook`] — the agent calls out before running a shell
//!   tool and honours a non-zero exit. In-path and blocking, but only as
//!   trustworthy as the agent: one that stops calling is not stopped by it.
//! * [`Mechanism::McpProxy`] — the agent speaks MCP and its config has a
//!   lossless editor, so `agents connect` rewrites it to run through the proxy.
//!   Automatic and reversible; covers agents with no hook surface at all.
//! * [`Mechanism::NotYetWirable`] — no hook AND no lossless editor for its
//!   config format, so nothing can be wired without risking the user's file.
//!   This is the honest gap, and naming it is what stops it being forgotten.
//! * [`Mechanism::Contain`] — no cooperative surface at all. Run it inside the
//!   sandbox, where the guard sits underneath it.
//!
//! Names match [`crate::signatures::KNOWN`] so a detected process and an install
//! target describe the same product to the operator.

use std::path::Path;

/// How the guardrail can get in front of a given agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    /// A settings file with a pre-tool hook that blocks on a non-zero exit.
    /// `settings_rel` is the home-relative path.
    SettingsHook { settings_rel: &'static str },
    /// No hook surface, but its MCP configuration can be rewritten to run
    /// through the proxy. `innerwarden agents connect` does that automatically;
    /// `why` explains why a hook is not the mechanism.
    ///
    /// `connect` is the name `agents connect` accepts, which is NOT always this
    /// target's id: the ids here follow the product names a user recognises
    /// (`codex-cli`), while [`crate::agents::KNOWN`] keys on the short name
    /// (`codex`). Printing the id sent the operator to a command that answered
    /// "no guardable agent named `codex-cli` was found" - advice that fails is
    /// worse than no advice, because it reads as "this cannot be protected".
    McpProxy {
        why: &'static str,
        connect: &'static str,
    },
    /// No hook, and its MCP config has no lossless editor yet, so nothing can be
    /// wired automatically. `why` names the blocker.
    NotYetWirable { why: &'static str },
    /// Not reachable cooperatively at all; isolation is the answer.
    Contain { why: &'static str },
}

#[derive(Debug, Clone, Copy)]
pub struct HookTarget {
    /// Value accepted by `install`. Kebab-case, stable.
    pub id: &'static str,
    /// Display name, matching `signatures::KNOWN`.
    pub display: &'static str,
    pub mechanism: Mechanism,
    /// Home-relative paths whose existence proves the agent has run here.
    /// Config directories, not binaries: a binary on PATH can be a leftover.
    pub markers: &'static [&'static str],
}

impl HookTarget {
    pub fn is_installed(&self, home: &Path) -> bool {
        self.markers.iter().any(|m| home.join(m).exists())
    }
}

pub static TARGETS: &[HookTarget] = &[
    HookTarget {
        id: "claude-code",
        display: "Claude Code",
        mechanism: Mechanism::SettingsHook {
            settings_rel: ".claude/settings.json",
        },
        markers: &[".claude", ".claude.json"],
    },
    HookTarget {
        id: "openclaw",
        display: "OpenClaw",
        // Established against the shipped build, not assumed: OpenClaw's own
        // hook events are command/session/agent/gateway/message, none of which
        // sees a proposed shell command, and its PreToolUse path is a relay of
        // whatever harness it drives. So a hook is not the mechanism for it.
        //
        // Its MCP servers live under a NESTED `mcp.servers`, which `mcp_wire`
        // learned to locate on 2026-08-05. A config that is not strict JSON is
        // refused by the reader rather than rewritten, so a genuinely JSON5 file
        // is left untouched.
        mechanism: Mechanism::McpProxy {
            why: "no tool gate of its own; it relays whichever harness it drives",
            connect: "openclaw",
        },
        markers: &[".openclaw", ".config/openclaw"],
    },
    HookTarget {
        id: "codex-cli",
        display: "Codex CLI",
        mechanism: Mechanism::McpProxy {
            why: "its `notify` hook fires AFTER a command runs, so it cannot block one",
            connect: "codex",
        },
        markers: &[".codex"],
    },
    HookTarget {
        id: "gemini-cli",
        display: "Gemini CLI",
        mechanism: Mechanism::McpProxy {
            why: "no pre-execution command hook is exposed",
            connect: "gemini",
        },
        markers: &[".gemini"],
    },
    HookTarget {
        id: "aider",
        display: "Aider",
        mechanism: Mechanism::Contain {
            why: "no pre-execution hook and no MCP surface",
        },
        markers: &[".aider.conf.yml", ".aider"],
    },
    HookTarget {
        id: "goose",
        display: "Goose",
        mechanism: Mechanism::NotYetWirable {
            why: "no pre-execution hook, and its MCP configuration has no lossless editor yet",
        },
        markers: &[".config/goose"],
    },
    HookTarget {
        id: "cursor",
        display: "Cursor",
        mechanism: Mechanism::McpProxy {
            why: "commands run inside the editor process; there is no host-side hook",
            connect: "cursor",
        },
        markers: &[".cursor"],
    },
    HookTarget {
        id: "windsurf",
        display: "Windsurf",
        // Advertised a connect command that has no target: `agents::KNOWN` has
        // no Windsurf row, so `agents connect windsurf` answers "no guardable
        // agent found". Wiring it needs its MCP config path CONFIRMED, not
        // guessed - writing to the wrong file is the one failure mode this
        // module must never have. Until then, isolation is the honest answer.
        mechanism: Mechanism::NotYetWirable {
            why: "no host-side hook, and its MCP config location is not confirmed here yet",
        },
        markers: &[".windsurf", ".codeium"],
    },
    HookTarget {
        id: "cline",
        display: "Cline",
        // Same as Windsurf: no `agents::KNOWN` row, so a connect command would
        // be a false promise.
        mechanism: Mechanism::NotYetWirable {
            why: "no host-side hook, and its MCP config location is not confirmed here yet",
        },
        markers: &[".cline"],
    },
    HookTarget {
        id: "openhands",
        display: "OpenHands",
        mechanism: Mechanism::Contain {
            why: "no pre-execution hook and no stable MCP surface",
        },
        markers: &[".openhands"],
    },
];

/// Look a target up by `install` id, or by the display name `agents` prints.
pub fn by_id(value: &str) -> Option<&'static HookTarget> {
    let needle = value.trim();
    TARGETS
        .iter()
        .find(|t| t.id.eq_ignore_ascii_case(needle) || t.display.eq_ignore_ascii_case(needle))
}

/// Every agent with a marker under `home`, in table order.
pub fn detect_installed(home: &Path) -> Vec<&'static HookTarget> {
    TARGETS.iter().filter(|t| t.is_installed(home)).collect()
}

/// Comma-separated ids, for error messages.
pub fn known_ids() -> String {
    TARGETS.iter().map(|t| t.id).collect::<Vec<_>>().join(", ")
}

/// The concrete next step for an agent that cannot take a settings hook.
///
/// A refusal with no remedy is what made the old message read as "cannot be
/// protected". Every branch here names a command that exists.
pub fn guidance(target: &HookTarget) -> String {
    match target.mechanism {
        Mechanism::SettingsHook { .. } => format!("innerwarden install {}", target.id),
        // `agents connect` rewrites the agent's MCP configuration to run through
        // the proxy, reversibly and idempotently. Telling the operator to invoke
        // `innerwarden proxy` by hand would send them the long way round a thing
        // the product already does for them.
        Mechanism::McpProxy { why, connect } => format!(
            "{}: {why}. Guard it through its MCP config:  innerwarden agents connect {connect}",
            target.display
        ),
        Mechanism::NotYetWirable { why } => format!(
            "{}: {why}. Run it isolated for now:  innerwarden contain -- <command>",
            target.display
        ),
        Mechanism::Contain { why } => format!(
            "{}: {why}. Run it isolated:  innerwarden contain -- <command>",
            target.display
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home_with(entries: &[&str]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        for e in entries {
            std::fs::create_dir_all(dir.path().join(e)).expect("mkdir");
        }
        dir
    }

    /// REGRESSION ANCHOR. `install` refused every agent but Claude Code, which
    /// on a host running anything else read as "InnerWarden cannot protect this".
    /// Every known agent must now resolve to a mechanism and a real command.
    ///
    /// FAILS ON REVERT: drop a target and its lookup returns None.
    #[test]
    fn every_known_agent_has_a_mechanism_and_a_real_next_step() {
        for t in TARGETS {
            let g = guidance(t);
            assert!(
                g.contains("innerwarden "),
                "{} must name a command, got: {g}",
                t.id
            );
            assert!(!t.markers.is_empty(), "{} can never be detected", t.id);
            assert_eq!(by_id(t.id).expect("resolves").display, t.display);
        }
    }

    #[test]
    fn detection_finds_only_what_is_installed() {
        let home = home_with(&[".openclaw", ".codex"]);
        let ids: Vec<_> = detect_installed(home.path()).iter().map(|t| t.id).collect();
        assert_eq!(ids, vec!["openclaw", "codex-cli"]);
        assert!(
            !ids.contains(&"claude-code"),
            "must not claim an agent that never ran here"
        );
    }

    #[test]
    fn an_empty_home_detects_nothing() {
        assert!(detect_installed(home_with(&[]).path()).is_empty());
    }

    /// `agents` prints display names, so pasting one back must work.
    #[test]
    fn lookup_accepts_id_and_display_name() {
        assert_eq!(by_id("openclaw").unwrap().display, "OpenClaw");
        assert_eq!(by_id("OpenClaw").unwrap().id, "openclaw");
        assert_eq!(by_id("  Claude Code ").unwrap().id, "claude-code");
        assert!(by_id("nope").is_none());
    }

    /// REGRESSION ANCHOR. An agent with no hook must be pointed at the mechanism
    /// that covers it, and at the AUTOMATIC form of it.
    ///
    /// `agents connect` already rewrites a supported agent's MCP configuration
    /// to run through the proxy, reversibly. Advice that said "run `innerwarden
    /// proxy -- <server>`" sent the operator the long way round something the
    /// product does for them, and made an automatic capability look manual.
    ///
    /// FAILS ON REVERT: point the McpProxy branch back at the raw proxy command.
    #[test]
    fn a_wirable_agent_is_pointed_at_the_automatic_path() {
        for id in ["cursor", "openclaw"] {
            let g = guidance(by_id(id).unwrap());
            assert!(
                g.contains(&format!("innerwarden agents connect {id}")),
                "{id} must name the automatic path, got: {g}"
            );
        }
        let g = guidance(by_id("cursor").unwrap());
        assert!(
            g.contains("innerwarden agents connect cursor"),
            "must name the automatic path, got: {g}"
        );
        assert!(
            !g.contains("innerwarden proxy --"),
            "must not send the operator to do it by hand: {g}"
        );
    }

    /// REGRESSION ANCHOR. `guidance` printed the target's own id, but
    /// `agents connect` matches against [`crate::agents::KNOWN`] names, which
    /// are shorter (`codex`, not `codex-cli`). So a host running Codex was told
    /// to run `innerwarden agents connect codex-cli`, which answered "no
    /// guardable agent named `codex-cli` was found". Two targets went further
    /// and advertised a connect for an agent with no KNOWN row at all.
    ///
    /// Advice that fails is worse than no advice: it reads as "this product
    /// cannot protect me". Every command this module prints must resolve.
    ///
    /// FAILS ON REVERT: print `target.id` again and Codex/Gemini stop resolving.
    #[test]
    fn every_command_the_guidance_prints_resolves_to_a_guardable_agent() {
        for target in TARGETS {
            let Mechanism::McpProxy { connect, .. } = target.mechanism else {
                continue;
            };
            let known = crate::agents::KNOWN
                .iter()
                .find(|k| k.name == connect)
                .unwrap_or_else(|| {
                    panic!(
                        "{} points `agents connect` at unknown `{connect}`",
                        target.id
                    )
                });
            assert!(
                known.mcp_json.is_some() || known.mcp_toml.is_some(),
                "{} is offered the MCP mechanism but `{connect}` has no MCP config to rewrite",
                target.id
            );
            assert!(
                guidance(target).contains(&format!("innerwarden agents connect {connect}")),
                "guidance must print the name the command accepts"
            );
        }
    }

    /// An agent with no hook AND no lossless config editor cannot be wired at
    /// all. That is the honest gap, and it must be routed to isolation rather
    /// than to a connect command that would silently do nothing.
    #[test]
    fn an_unwirable_agent_is_routed_to_isolation() {
        // Goose keeps its servers in YAML, which no writer here round-trips.
        {
            let id = "goose";
            let g = guidance(by_id(id).unwrap());
            assert!(
                g.contains("innerwarden contain"),
                "{id} has nothing to wire yet, so it must be isolated: {g}"
            );
            assert!(
                !g.contains("agents connect"),
                "{id} cannot be connected; offering it would be a false promise: {g}"
            );
        }
        let g = guidance(by_id("aider").unwrap());
        assert!(g.contains("innerwarden contain"), "got: {g}");
    }

    #[test]
    fn ids_are_unique() {
        let mut ids: Vec<_> = TARGETS.iter().map(|t| t.id).collect();
        let n = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), n, "duplicate install id");
    }
}
