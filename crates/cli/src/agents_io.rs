//! `innerwarden agents` for Community Edition - a thin wrapper over the shared
//! agent discovery/wiring engine plus the persisted Community auto-connect policy.

use innerwarden_agent_guard::{agents_ops, hook};

use crate::agent_policy::{self, DesiredMode};

/// `innerwarden agents [connect|disconnect [--all|<name>]]` - discover + connect.
pub fn cmd(rest: &[String]) -> std::process::ExitCode {
    if matches!(rest, [flag] if flag == "--help" || flag == "-h") {
        print_agents_help();
        return std::process::ExitCode::SUCCESS;
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
        println!("{}", crate::RESTART_GUARDED_AGENTS);
    }
    if failed {
        std::process::ExitCode::from(1)
    } else {
        std::process::ExitCode::SUCCESS
    }
}

fn is_known_agent_name(name: &str) -> bool {
    innerwarden_agent_guard::agents::KNOWN
        .iter()
        .any(|known| known.name.eq_ignore_ascii_case(name))
}

fn print_agents_help() {
    println!("innerwarden agents [list]");
    println!("innerwarden agents connect [<name>|--all] [--monitor|--strict]");
    println!("innerwarden agents disconnect [<name>|--all]");
    println!("innerwarden agents auto-connect [--monitor|--off|status]");
    println!("  Automatic setup is opt-in and monitor-only; unknown flags fail without changes.");
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

    if matches!(rest, [flag] if flag == "--help" || flag == "-h") {
        print_auto_connect_help();
        return std::process::ExitCode::SUCCESS;
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

fn print_auto_connect_help() {
    println!("innerwarden agents auto-connect [--monitor|--off|status]");
    println!("  opt in to background discovery while the local dashboard runs");
    println!("  --monitor   connect newly discovered supported agents in observe-only mode");
    println!("  --off       stop future automatic wiring; existing integrations stay configured");
    println!("  status      show policy schema, state, interval, and explicit exclusions");
    println!("  New wiring and misplaced-only hook repairs are monitor-only.");
    println!(
        "  Recognized Claude hooks may be canonicalized; effective Bash enforcement is preserved."
    );
    println!(
        "  Existing MCP wrappers and excluded, unknown, or invalid integrations are unchanged."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

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
