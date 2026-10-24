//! `innerwarden agents` for Community Edition - a thin wrapper over the shared
//! agent discovery/wiring engine plus the persisted Community auto-connect policy.

use innerwarden_agent_guard::{agents_ops, hook};

use crate::agent_policy::{self, DesiredMode};

/// `innerwarden agents [connect|disconnect [--all|<name>]]` - discover + connect.
/// PURE. Whether `innerwarden agents <rest>` lowers a guard: a disconnect, or
/// a connect in monitor.
pub(crate) fn lowers_a_guard(rest: &[String]) -> bool {
    match rest.first().map(String::as_str) {
        Some("disconnect") => true,
        Some("connect") => rest.iter().any(|a| a == "--monitor"),
        _ => false,
    }
}

pub fn cmd(rest: &[String]) -> std::process::ExitCode {
    // The person's decisions about an agent (approve, profile, allow,
    // revoke): verbs of their own, never part of discovery or wiring.
    if rest.first().is_some_and(|verb| {
        innerwarden_agent_guard::threats::AGENT_DECISION_VERBS.contains(&verb.as_str())
    }) {
        return crate::agent_decisions_io::cmd(rest);
    }
    if rest.first().map(String::as_str) != Some("auto-connect") {
        if let Err(error) = agents_ops::validate_args(rest) {
            eprintln!("innerwarden agents: {error}");
            print_agents_help();
            return std::process::ExitCode::from(2);
        }
    }
    let home = match hook::home_dir() {
        Ok(home) => home,
        Err(error) => {
            eprintln!("innerwarden agents: {error}");
            return std::process::ExitCode::from(2);
        }
    };
    if rest.first().map(String::as_str) == Some("auto-connect") {
        return cmd_auto_connect(&home, &rest[1..]);
    }

    // Taking the hook off an agent, or rewiring it to record only, lowers the
    // guard that screens it: the person's, never a command an AI agent's
    // shell runs (live gate of Active Defence 0.17.4, G1). The guard refuses
    // the agent running it; this holds where the guard cannot see the call.
    if lowers_a_guard(rest) && crate::suppress_io::in_agent_shell() {
        eprintln!(
            "innerwarden agents: refused inside an AI agent's shell. Disconnecting an agent, \
             or connecting it in monitor, lowers the guard that screens it, so it is done \
             by the person, from their own terminal. Nothing was changed."
        );
        return std::process::ExitCode::from(1);
    }
    let mutating = matches!(
        rest.first().map(String::as_str),
        Some("connect" | "disconnect")
    );
    if mutating {
        if let Some(target) = command_target(rest) {
            let found = agents_ops::rows(&home)
                .iter()
                .any(|agent| agent.guardable() && agent.name.eq_ignore_ascii_case(target));
            if !found {
                if rest.first().map(String::as_str) == Some("disconnect")
                    && is_known_agent_name(target)
                {
                    match agent_policy::with_lock(&home, || {
                        agent_policy::exclude_agent(&home, target).map(|_| ())
                    }) {
                        Ok(()) => {
                            println!(
                                "  {target} - not currently detected; excluded from future automatic setup"
                            );
                            return std::process::ExitCode::SUCCESS;
                        }
                        Err(error) => {
                            eprintln!("innerwarden agents: {error}");
                            return std::process::ExitCode::from(1);
                        }
                    }
                }
                eprintln!(
                    "innerwarden agents: no guardable agent named `{target}` was found; policy and agent configurations were left unchanged"
                );
                return std::process::ExitCode::from(1);
            }
        }
    }
    let outcome = if mutating {
        match agent_policy::with_lock(&home, || {
            prepare_policy_for_agent_command(&home, rest)?;
            Ok(agents_ops::run_outcome(&home, rest))
        }) {
            Ok(outcome) => outcome,
            Err(error) => {
                eprintln!("innerwarden agents: {error}");
                return std::process::ExitCode::from(1);
            }
        }
    } else {
        agents_ops::run_outcome(&home, rest)
    };
    let failed = outcome.lines.iter().any(|line| line.contains("failed:"));
    for line in &outcome.lines {
        println!("{line}");
    }
    // An agent reads its hook / MCP configuration at STARTUP. Without this the
    // command printed "connected" and the user went back to a session that was
    // still running unscreened, believing it was protected.
    //
    // The count comes from the engine's own `ConnectEffect`, never from scanning
    // the lines above, and it is zero for `disconnect`, so nobody is told to
    // restart after deliberately unwiring. Same wording as `dry-run`/`enforce`
    // so the product says one thing.
    if outcome.configured > 0 {
        let target = command_target(rest);
        let connected: Vec<String> = agents_ops::rows(&home)
            .into_iter()
            .filter(|agent| {
                agent.guardable()
                    && agent.guarded
                    && target.is_none_or(|name| agent.name.eq_ignore_ascii_case(name))
            })
            .map(|agent| agent.name)
            .collect();
        for line in restart_footer(&connected) {
            println!("{line}");
        }
    }
    if failed {
        std::process::ExitCode::from(1)
    } else {
        std::process::ExitCode::SUCCESS
    }
}

/// How to restart one agent so it reads its changed hook or MCP config, and
/// why that is needed. The person restarts it: nothing here says it was.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct RestartWords {
    pub how: String,
    pub why: &'static str,
}

/// Why a running agent needs a restart after its config changed.
pub(crate) const RESTART_WHY: &str = "An agent reads its hook or MCP config only when it starts.";

/// The restart words for one agent: Claude Code and Codex by their own
/// steps, any other agent by the generic one, named by `display_name`.
pub(crate) fn restart_words(agent_id: &str, display_name: &str) -> RestartWords {
    let how = match agent_id {
        "claude-code" | "claude" => "In Claude Code, type /exit, then run claude.".to_string(),
        "codex" => "Quit Codex and start it again.".to_string(),
        _ => format!("Quit {display_name} and start it again."),
    };
    RestartWords {
        how,
        why: RESTART_WHY,
    }
}

/// What a command that changed agents' configs prints at its end: the
/// shared restart line, byte for byte as it always was, then one line per
/// agent saying how to restart that one. Each agent once, in the order given.
pub(crate) fn restart_footer(agent_ids: &[String]) -> Vec<String> {
    let mut lines = vec![crate::RESTART_GUARDED_AGENTS.to_string()];
    let mut seen: Vec<&str> = Vec::new();
    for id in agent_ids {
        if seen.contains(&id.as_str()) {
            continue;
        }
        seen.push(id);
        let name = crate::dashboard_community::agent_name(id);
        lines.push(format!("  {name}: {}", restart_words(id, &name).how));
    }
    lines
}

fn is_known_agent_name(name: &str) -> bool {
    innerwarden_agent_guard::agents::KNOWN
        .iter()
        .any(|known| known.name.eq_ignore_ascii_case(name))
}

/// Usage for `innerwarden agents`. Printed by `help::for_invocation` before
/// dispatch, and by the error paths below when an argument was not understood.
pub(crate) fn help_text() -> String {
    let p = crate::prog();
    format!(
        "{p} agents [list]\n\
         {p} agents connect [<name>|--all] [--monitor|--strict]\n\
         {p} agents disconnect [<name>|--all]\n\
         {p} agents auto-connect [--monitor|--off|status]\n\
         {decisions}\n\
         \n  \
         Find the AI agents on this machine and wire the guard into them.\n  \
         Automatic setup is opt-in and monitor-only; unknown flags fail without\n  \
         changing anything.\n  \
         approve, profile, allow and revoke record your decisions about a type of\n  \
         agent in agent-profiles.toml, confirmed at your terminal. Only\n  \
         /etc/innerwarden/agent-profiles.toml (--system, as root) may relax a rule,\n  \
         and a relaxation applies only to an instance that runs confined. Confined\n  \
         needs a witness outside the jail (InnerWarden Pro): read from inside the\n  \
         jail an instance is at most observed, so with Community alone a relaxation\n  \
         is recorded and your general rules keep deciding.",
        decisions = crate::agent_decisions::usage()
    )
}

fn print_agents_help() {
    println!("{}", help_text());
}

fn command_target(rest: &[String]) -> Option<&str> {
    rest.iter()
        .skip(1)
        .find(|arg| !arg.starts_with("--"))
        .map(String::as_str)
}

/// Persist operator intent before changing third-party configuration. This order
/// prevents a dashboard reconcile from undoing an explicit disconnect, including
/// when the subsequent unwrap itself fails.
fn prepare_policy_for_agent_command(home: &std::path::Path, rest: &[String]) -> Result<(), String> {
    match rest.first().map(String::as_str) {
        Some("connect") => {
            if let Some(name) = command_target(rest) {
                agent_policy::include_agent(home, name)?;
            }
        }
        Some("disconnect") => {
            let explicit_all = rest.iter().skip(1).any(|arg| arg == "--all");
            match command_target(rest) {
                Some(name) if !explicit_all => {
                    agent_policy::exclude_agent(home, name)?;
                }
                _ => {
                    // `disconnect` without a target has the shared engine's all
                    // semantics, so disable future auto-connect before unwrapping.
                    agent_policy::disable_auto_connect(home)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn cmd_auto_connect(home: &std::path::Path, rest: &[String]) -> std::process::ExitCode {
    if rest.is_empty() || matches!(rest, [command] if command == "status") {
        return print_auto_connect_status(home);
    }

    let enabled = match rest {
        [flag] if flag == "--monitor" => true,
        [flag] if flag == "--off" => false,
        _ => {
            eprintln!(
                "innerwarden agents auto-connect: expected --monitor, --off, or status (automatic wiring is monitor-only)"
            );
            print_auto_connect_help();
            return std::process::ExitCode::from(2);
        }
    };

    let policy = match agent_policy::with_lock(home, || {
        agent_policy::set_auto_connect(home, enabled, DesiredMode::Monitor)
    }) {
        Ok(policy) => policy,
        Err(error) => {
            eprintln!("innerwarden agents auto-connect: {error}");
            return std::process::ExitCode::from(1);
        }
    };
    if !enabled {
        println!("innerwarden agents auto-connect - disabled; existing wiring was left unchanged");
        return std::process::ExitCode::SUCCESS;
    }

    let guard_bin = agents_ops::guard_bin();
    let report = agent_policy::reconcile(home, &guard_bin, &policy);
    for notice in &report.notices {
        println!("{notice}");
    }
    println!(
        "innerwarden agents auto-connect - enabled (monitor-only); {} detected, {} connected now, {} skipped",
        report.detected, report.connected, report.skipped
    );
    println!(
        "  New supported agents are checked every {}s while `innerwarden dashboard` is running.",
        agent_policy::RECONCILE_INTERVAL_SECS
    );
    println!("  New connections and misplaced-only Claude hook repairs stay in monitor mode.");
    println!("  Recognized Claude hooks may be canonicalized without downgrading an effective Bash mode;");
    println!(
        "  existing MCP wrappers and excluded, unknown, or invalid integrations stay unchanged."
    );
    if report.has_failures() {
        eprintln!(
            "innerwarden agents auto-connect: {} automatic connection attempt(s) failed",
            report.failed
        );
        std::process::ExitCode::from(1)
    } else {
        std::process::ExitCode::SUCCESS
    }
}

fn print_auto_connect_status(home: &std::path::Path) -> std::process::ExitCode {
    match agent_policy::load(home) {
        Ok(policy) => {
            if policy.auto_connect {
                println!(
                    "innerwarden agents auto-connect - enabled (monitor-only, every {}s while the dashboard runs)",
                    agent_policy::RECONCILE_INTERVAL_SECS
                );
            } else {
                println!("innerwarden agents auto-connect - disabled");
            }
            println!("  schema: {}", policy.schema_version);
            if policy.excluded.is_empty() {
                println!("  excluded agents: none");
            } else {
                println!("  excluded agents: {}", policy.excluded.join(", "));
            }
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("innerwarden agents auto-connect: {error}");
            std::process::ExitCode::from(1)
        }
    }
}

/// Usage for the nested `innerwarden agents auto-connect`. Printed by
/// `help::for_invocation` before dispatch, and by the error path above.
pub(crate) fn auto_connect_help_text() -> String {
    let p = crate::prog();
    format!(
        "{p} agents auto-connect [--monitor|--off|status]\n  \
         Opt in to background discovery while the local dashboard runs.\n\
         \n  \
         --monitor   connect newly discovered supported agents in observe-only mode\n  \
         --off       stop future automatic wiring; existing integrations stay configured\n  \
         status      show policy schema, state, interval, and explicit exclusions\n\
         \n  \
         New wiring and misplaced-only hook repairs are monitor-only.\n  \
         Recognized Claude hooks may be canonicalized; effective Bash enforcement is\n  \
         preserved. Existing MCP wrappers and excluded, unknown, or invalid\n  \
         integrations are unchanged."
    )
}

fn print_auto_connect_help() {
    println!("{}", auto_connect_help_text());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Claude Code and Codex get their own steps; any other agent the
    /// generic one under its own name. Every one says why.
    #[test]
    fn restart_words_cover_claude_code_codex_and_a_generic_agent() {
        assert_eq!(
            restart_words("claude-code", "Claude Code"),
            RestartWords {
                how: "In Claude Code, type /exit, then run claude.".into(),
                why: "An agent reads its hook or MCP config only when it starts.",
            }
        );
        assert_eq!(
            restart_words("codex", "Codex").how,
            "Quit Codex and start it again."
        );
        assert_eq!(
            restart_words("gemini", "Gemini CLI").how,
            "Quit Gemini CLI and start it again."
        );
        assert_eq!(restart_words("gemini", "Gemini CLI").why, RESTART_WHY);
    }

    /// The person restarts the agent; no word says it happened, or that a
    /// change was taken up.
    #[test]
    fn restart_words_never_say_restarted_or_reloaded() {
        for (id, name) in [
            ("claude-code", "Claude Code"),
            ("codex", "Codex"),
            ("cursor", "Cursor"),
            ("openclaw", "OpenClaw"),
            ("some-agent", "Some Agent"),
        ] {
            let words = restart_words(id, name);
            let text = format!("{} {}", words.how, words.why).to_lowercase();
            for banned in [
                "restarted",
                "reloaded",
                "picked up",
                "now protected",
                "protected",
            ] {
                assert!(!text.contains(banned), "{id}: {text}");
            }
            assert!(!text.contains('\u{2014}') && !text.contains('\u{2013}'));
        }
    }

    /// After a mode switch or a connect: the shared restart line exactly as
    /// it always was, then one line per agent whose config changed, each
    /// once. FAILS ON REVERT of the per-agent lines: only the shared line is
    /// printed.
    #[test]
    fn mode_switch_prints_each_connected_agents_restart_words() {
        let lines = restart_footer(&[
            "claude-code".to_string(),
            "codex".to_string(),
            "claude-code".to_string(),
            "cursor".to_string(),
        ]);
        assert_eq!(
            lines,
            vec![
                "  Restart guarded agents so they reload their hook or MCP configuration."
                    .to_string(),
                "  Claude Code: In Claude Code, type /exit, then run claude.".to_string(),
                "  Codex: Quit Codex and start it again.".to_string(),
                "  Cursor: Quit Cursor and start it again.".to_string(),
            ]
        );
        assert_eq!(lines[0], crate::RESTART_GUARDED_AGENTS);
        assert_eq!(restart_footer(&[]), vec![crate::RESTART_GUARDED_AGENTS]);
    }

    #[test]
    fn disconnect_excludes_connect_includes_and_disconnect_all_disables() {
        let home = tempfile::TempDir::new().unwrap();
        agent_policy::set_auto_connect(home.path(), true, DesiredMode::Monitor).unwrap();

        prepare_policy_for_agent_command(home.path(), &["disconnect".into(), "Cursor".into()])
            .unwrap();
        let excluded = agent_policy::load(home.path()).unwrap();
        assert!(excluded.auto_connect);
        assert_eq!(excluded.excluded, vec!["cursor"]);

        prepare_policy_for_agent_command(home.path(), &["connect".into(), "cursor".into()])
            .unwrap();
        assert!(agent_policy::load(home.path()).unwrap().excluded.is_empty());

        prepare_policy_for_agent_command(home.path(), &["disconnect".into(), "--all".into()])
            .unwrap();
        assert!(!agent_policy::load(home.path()).unwrap().auto_connect);
    }

    #[test]
    fn connect_all_preserves_explicit_exclusions() {
        let home = tempfile::TempDir::new().unwrap();
        agent_policy::exclude_agent(home.path(), "cursor").unwrap();
        prepare_policy_for_agent_command(
            home.path(),
            &["connect".into(), "--all".into(), "--monitor".into()],
        )
        .unwrap();
        assert_eq!(
            agent_policy::load(home.path()).unwrap().excluded,
            vec!["cursor"]
        );
    }

    #[test]
    fn preventive_disconnect_names_are_exact_not_fuzzy() {
        assert!(is_known_agent_name("Cursor"));
        assert!(is_known_agent_name("claude-code"));
        assert!(!is_known_agent_name("cursor-mcp"));
        assert!(!is_known_agent_name("c"));
    }
}
