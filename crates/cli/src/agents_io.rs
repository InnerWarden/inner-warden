//! `innerwarden agents` for Community Edition - a thin wrapper over the shared
//! agent discovery/wiring engine plus the persisted Community auto-connect policy.

use std::path::Path;

use innerwarden_agent_guard::{agent_hooks, agents_ops, hermes_hook, hook};

use crate::agent_policy::{self, DesiredMode};

/// `innerwarden agents [connect|disconnect [--all|<name>]]` - discover + connect.
/// PURE. Whether `innerwarden agents <rest>` lowers a guard: a disconnect, or
/// a connect in monitor or in the default posture asked for by name
/// (`--guard`, which moves a strict install to it).
pub(crate) fn lowers_a_guard(rest: &[String]) -> bool {
    match rest.first().map(String::as_str) {
        Some("disconnect") => true,
        Some("connect") => rest.iter().any(|a| a == "--monitor" || a == "--guard"),
        _ => false,
    }
}

/// Whether the guard's hook for the agent named `name` under `home` also
/// refuses `review` (`--block-review`). A switch of mode passes this on,
/// so it rewrites the line in the mode asked for and never drops the flag:
/// only the person, with `agents connect` or `install` from their own
/// terminal, takes it off.
pub(crate) fn wiring_blocks_review(home: &Path, name: &str) -> bool {
    if name == hermes_hook::AGENT {
        return match hermes_hook::state(home, None) {
            hermes_hook::State::On { block_review, .. } => block_review,
            // A line not read as on is kept as written when it names the
            // flag: keeping it never refuses less.
            _ => std::fs::read_to_string(hermes_hook::config_path(home))
                .is_ok_and(|text| text.contains("--block-review")),
        };
    }
    let files: Vec<std::path::PathBuf> = if name == "claude-code" {
        [".claude/settings.json", ".claude/settings.local.json"]
            .iter()
            .map(|rel| home.join(rel))
            .collect()
    } else {
        [&agent_hooks::CODEX, &agent_hooks::GEMINI]
            .into_iter()
            .filter(|spec| spec.agent == name)
            .map(|spec| spec.path(home))
            .collect()
    };
    files
        .iter()
        .filter_map(|path| std::fs::read(path).ok())
        .filter_map(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .any(|settings| hook::holds_a_block_review_line(&settings))
}

/// Whether any agent's hook under `home` refuses `review`
/// ([`wiring_blocks_review`]).
pub(crate) fn any_wiring_blocks_review(home: &Path) -> bool {
    [
        "claude-code",
        agent_hooks::CODEX.agent,
        agent_hooks::GEMINI.agent,
        hermes_hook::AGENT,
    ]
    .iter()
    .any(|name| wiring_blocks_review(home, name))
}

/// PURE: the `guard.mode_changed` line for a change of what the guard
/// refuses: `command` as typed (`enforce`, `dry-run`, `agents connect`,
/// `agents disconnect`), the `mode` it set, the posture it asked for, the
/// agents it reached, and whether it ran inside an AI agent's shell.
pub(crate) fn mode_change_line(
    ts: u64,
    change: &ModeChange<'_>,
    from_agent_shell: bool,
    session: &str,
) -> serde_json::Value {
    serde_json::json!({
        "kind": "guard.mode_changed",
        "ts": ts,
        "command": change.command,
        "mode": change.mode,
        "posture": change.posture,
        "agents": change.agents,
        "from_agent_shell": from_agent_shell,
        "session": session,
    })
}

/// PURE: the words a configured channel gets for [`ModeChange`].
pub(crate) fn mode_change_text(change: &ModeChange<'_>, from_agent_shell: bool) -> String {
    let agents = if change.agents.is_empty() {
        "no agent".to_string()
    } else {
        change.agents.join(", ")
    };
    let posture = change
        .posture
        .map(|word| format!(", posture {word}"))
        .unwrap_or_default();
    let who = if from_agent_shell {
        " It was run inside an AI agent's shell."
    } else {
        ""
    };
    format!(
        "InnerWarden: the guard's mode changed on this machine. `innerwarden {}` set {}{posture} for {agents}.{who} If this was not you, run `innerwarden status`.",
        change.command, change.mode
    )
}

/// One change of what the guard refuses, as [`record_mode_change`] tells it.
pub(crate) struct ModeChange<'a> {
    pub command: &'a str,
    pub mode: &'a str,
    pub posture: Option<&'a str>,
    pub agents: Vec<String>,
}

/// Record a change of mode or posture in `guard-events.jsonl` and tell the
/// configured channels. A switch that refuses less, done without a trace,
/// is the one change a person most needs to hear about, so every switch is
/// recorded and sent, raising ones too. Best-effort, like every line of the
/// record: neither can undo or block the change it reports.
pub(crate) fn record_mode_change(change: &ModeChange<'_>) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let in_shell = crate::suppress_io::in_agent_shell();
    crate::graph_io::append_guard_event(&mode_change_line(
        ts,
        change,
        in_shell,
        &crate::graph_io::session_id(None),
    ));
    crate::notify_io::fire_text(&mode_change_text(change, in_shell));
}

/// The program this process was started as, the way the hook line names it:
/// `argv[0]` when it is an absolute path (the hook line and the upgrade both
/// run an absolute path), else the resolved executable. Rewiring to the
/// resolved path instead would turn a hook that names a symlink or a package
/// shim into one that names whatever it points at today.
pub(crate) fn invoked_as() -> Option<String> {
    let argv0 = std::env::args_os().next().map(std::path::PathBuf::from);
    match argv0 {
        Some(path) if path.is_absolute() => Some(path.display().to_string()),
        _ => std::env::current_exe()
            .ok()
            .map(|p| p.display().to_string()),
    }
}

/// `innerwarden agents rewire`: bring the wiring already there up to this
/// binary's, in the mode it has ([`agent_policy::rewire_existing`]). Connects
/// no new agent; for an agent already connected it writes the halves it lacks
/// in the mode of its Bash half, keeps each other half's mode and never lowers
/// one, so it is not one of the verbs that lower a guard. The upgrade runs it with the NEW binary.
fn cmd_rewire() -> std::process::ExitCode {
    let (Ok(home), Some(bin)) = (hook::home_dir(), invoked_as()) else {
        eprintln!("innerwarden agents rewire: could not tell the home or this program's path");
        return std::process::ExitCode::from(1);
    };
    let report = agent_policy::rewire_existing(&home, &bin);
    for line in &report.notices {
        println!("{line}");
    }
    if report.connected > 0 {
        println!(
            "Re-wired {} connected agent(s) so this version's hooks are the ones they run.",
            report.connected
        );
        println!("Restart them to pick it up: a hook is read at agent startup.");
    }
    if report.failed > 0 {
        std::process::ExitCode::from(1)
    } else if report.refused {
        // Not a failure of the command, but the wiring was left as it was:
        // the upgrade reads this code to say so and how to rewire.
        std::process::ExitCode::from(3)
    } else {
        std::process::ExitCode::SUCCESS
    }
}

/// Once per version of this binary at its path: [`agent_policy::rewire_existing`],
/// from the hook.
///
/// The upgrade now rewires with the new binary, but a host upgraded by an
/// older one (1.6.12 to 1.6.13, any `npm`, `deb` or copied binary) never ran
/// that, and the hook is the one part of the new binary sure to run. A stamp
/// beside the agent policy records the version and path that last rewired, so
/// every later call costs one small read. Before any rewire, a call reads
/// Claude Code's settings and writes nothing when there is nothing of ours to
/// bring up to date. A run that failed or could not take the lock writes no
/// stamp and is tried again on the next call. Silent: what it changed is said
/// by `status` and `agents`.
pub(crate) fn rewire_once_per_version() {
    let (Ok(home), Some(bin)) = (hook::home_dir(), invoked_as()) else {
        return;
    };
    let bin = agent_policy::wired_name_of(&home, &bin);
    let stamp = agent_policy::config_path(&home).with_file_name("rewired");
    let want = format!("{} {bin}\n", env!("CARGO_PKG_VERSION"));
    if std::fs::read_to_string(&stamp).is_ok_and(|have| have == want) {
        return;
    }
    // A cargo build, or a binary the hooks do not run: leave the home
    // exactly as it is, stamp included.
    if agent_policy::refuse_rewire_to(&home, &bin).is_some() {
        return;
    }
    // Nothing of ours to bring up to date: write nothing, not even the
    // stamp, so a hook on a home with no wiring leaves no file behind.
    if !agent_policy::claude_wiring_needs_rewire(&home, &bin) {
        return;
    }
    let report =
        agent_policy::rewire_existing_within(&home, &bin, std::time::Duration::from_millis(50));
    if !report.has_failures() {
        let _ = std::fs::write(&stamp, want);
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
    if rest.first().map(String::as_str) == Some("rewire") {
        return cmd_rewire();
    }
    // The posture flags are this command's own: the wiring engine, which
    // Active Defence shares, reads `--strict` as `--block-review`.
    let original = rest;
    let connecting = rest.first().map(String::as_str) == Some("connect");
    let posture_asked = if connecting {
        match crate::posture_io::requested(rest) {
            Ok(asked) => asked,
            Err(error) => {
                eprintln!("innerwarden agents: {error}");
                return std::process::ExitCode::from(2);
            }
        }
    } else {
        None
    };
    if posture_asked.is_some() && rest.iter().any(|a| a == "--monitor") {
        eprintln!(
            "innerwarden agents: `--monitor` refuses nothing, so it takes no posture; \
             choose `--monitor` or a posture"
        );
        return std::process::ExitCode::from(2);
    }
    let stripped = if connecting {
        crate::posture_io::without_posture_flags(rest)
    } else {
        rest.to_vec()
    };
    let rest = stripped.as_slice();
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
    if lowers_a_guard(original) && crate::suppress_io::in_agent_shell() {
        eprintln!(
            "innerwarden agents: refused inside an AI agent's shell. Disconnecting an agent, \
             or connecting it in monitor or with --guard, lowers the guard that screens it, so \
             it is done by the person, from their own terminal. Nothing was changed."
        );
        return std::process::ExitCode::from(1);
    }
    // A connect from an AI agent's shell that names no mode writes the line
    // in enforce, which over a line that also refuses `review` refuses
    // less. Run there, it keeps `--block-review`: only the person, from
    // their own terminal, takes it off.
    let kept: Vec<String>;
    let rest = if connecting
        && crate::suppress_io::in_agent_shell()
        && !rest
            .iter()
            .any(|a| a == "--monitor" || a == "--block-review" || a == "--strict")
        && any_wiring_blocks_review(&home)
    {
        kept = rest
            .iter()
            .cloned()
            .chain(std::iter::once("--block-review".to_string()))
            .collect();
        kept.as_slice()
    } else {
        rest
    };
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
    // Read before anything is wired: whether this is a new install.
    let was_wired = connecting && crate::posture_io::already_wired(&home);
    let outcome = if mutating {
        match agent_policy::with_lock(&home, || {
            prepare_policy_for_agent_command(&home, rest)?;
            let mut outcome = agents_ops::run_outcome(&home, rest);
            // OpenClaw's own tools never reach the MCP proxy: the plugin
            // that screens them goes in (and out) next to it.
            outcome.lines.extend(openclaw_guard_lines(&home, rest));
            Ok(outcome)
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
    if mutating {
        if let Some(mode) = mode_set_by(rest, posture_asked) {
            record_mode_change(&ModeChange {
                command: if connecting {
                    "agents connect"
                } else {
                    "agents disconnect"
                },
                mode,
                posture: posture_asked.map(|posture| posture.word()),
                agents: vec![command_target(rest).unwrap_or("all").to_string()],
            });
        }
    }
    if connecting && !failed {
        match crate::posture_io::settle(&home, posture_asked, was_wired) {
            Ok(line) => println!("{line}"),
            Err(error) => {
                eprintln!("innerwarden agents: the posture was not written: {error}");
                return std::process::ExitCode::from(1);
            }
        }
    }
    if matches!(rest.first().map(String::as_str), None | Some("list"))
        && crate::observe_io::openclaw_config(&home).is_file()
    {
        println!();
        for line in crate::openclaw_guard_io::status_lines(&home) {
            println!("{line}");
        }
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
/// shared restart line, byte for byte as it always was, why ([`RESTART_WHY`]),
/// then one line per agent saying how to restart that one. Each agent once,
/// in the order given; with none named, how to restart any of them.
pub(crate) fn restart_footer(agent_ids: &[String]) -> Vec<String> {
    let mut lines = vec![
        crate::RESTART_GUARDED_AGENTS.to_string(),
        format!("  {RESTART_WHY}"),
    ];
    if agent_ids.is_empty() {
        lines.push("  Quit each guarded agent and start it again.".to_string());
    }
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
         {p} agents connect [<name>|--all] [--monitor|--strict|--guard|--block-review]\n\
         {p} agents disconnect [<name>|--all]\n\
         {p} agents auto-connect [--monitor|--off|status]\n\
         {decisions}\n\
         \n  \
         Find the AI agents on this machine and wire the guard into them.\n  \
         A new install starts in the default posture: it refuses a hard secret read,\n  \
         destruction of the system or a home, an act that takes the guard down, a\n  \
         reverse shell and download-and-run; every other deny or review runs with a\n  \
         one-line warning and is recorded. An install from an earlier version keeps\n  \
         refusing every deny.\n  \
         --strict        refuse every deny and every review (the --block-review\n  \
         \x20               wiring of earlier versions' --strict)\n  \
         --guard         move a strict install to the default hook posture (your terminal only)\n  \
         --block-review  refuse every review too\n  \
         --monitor       record every call and refuse nothing\n  \
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

/// PURE. Whether an `agents connect` or `disconnect` reaches OpenClaw: it
/// names it, or names no agent (every agent detected).
pub(crate) fn names_openclaw(rest: &[String]) -> bool {
    command_target(rest).is_none_or(|name| name.eq_ignore_ascii_case("openclaw"))
}

/// The guard plugin, installed by a connect that reaches a detected OpenClaw
/// (in monitor unless the entry holds a mode, and in monitor with
/// `--monitor`), taken out by a disconnect that reaches it.
fn openclaw_guard_lines(home: &std::path::Path, rest: &[String]) -> Vec<String> {
    use crate::openclaw_guard::Mode;
    use crate::openclaw_guard_io as guard;
    if !names_openclaw(rest) {
        return Vec::new();
    }
    match rest.first().map(String::as_str) {
        Some("connect") => {
            let detected = agents_ops::rows(home)
                .iter()
                .any(|agent| agent.guardable() && agent.name.eq_ignore_ascii_case("openclaw"));
            if !detected {
                return Vec::new();
            }
            let mut installed = guard::install(home, &agents_ops::guard_bin());
            if rest.iter().any(|a| a == "--monitor") {
                if let guard::Installed::Enabled { mode, .. } = &mut installed {
                    match guard::set_mode(home, Mode::Monitor) {
                        Ok(_) => *mode = Mode::Monitor,
                        Err(error) => installed = guard::Installed::Failed(error),
                    }
                }
            }
            guard::install_lines(&installed, home)
        }
        Some("disconnect") => guard::uninstall(home),
        _ => Vec::new(),
    }
}

/// PURE: the mode an `agents` command sets when it changes what the guard
/// refuses: a disconnect, a connect in monitor, or a connect that names a
/// posture. `None` for a connect that leaves the mode as it was asked
/// before.
fn mode_set_by(
    rest: &[String],
    posture: Option<innerwarden_agent_guard::posture::Posture>,
) -> Option<&'static str> {
    match rest.first().map(String::as_str) {
        Some("disconnect") => Some("off"),
        Some("connect") if rest.iter().any(|a| a == "--monitor") => Some("monitor"),
        Some("connect") => match posture {
            Some(innerwarden_agent_guard::posture::Posture::Strict) => Some("block-review"),
            Some(innerwarden_agent_guard::posture::Posture::Default) => Some("enforce"),
            None => None,
        },
        _ => None,
    }
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
                "  An agent reads its hook or MCP config only when it starts.".to_string(),
                "  Claude Code: In Claude Code, type /exit, then run claude.".to_string(),
                "  Codex: Quit Codex and start it again.".to_string(),
                "  Cursor: Quit Cursor and start it again.".to_string(),
            ]
        );
        assert_eq!(lines[0], crate::RESTART_GUARDED_AGENTS);
        // With no agent named the footer still says why and how.
        // (NEW-20261023-restart-guarded-agents-says-not-how)
        let none = restart_footer(&[]);
        assert_eq!(none[0], crate::RESTART_GUARDED_AGENTS);
        assert!(
            none.iter().any(|l| l.contains("only when it starts")),
            "{none:?}"
        );
        assert!(
            none.iter().any(|l| l.contains("start it again")),
            "{none:?}"
        );
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

#[cfg(test)]
mod openclaw_guard_tests {
    use super::names_openclaw;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// A connect or disconnect that names OpenClaw, or names no agent,
    /// reaches the guard plugin; one naming another agent does not.
    #[test]
    fn the_guard_follows_a_connect_that_reaches_openclaw() {
        assert!(names_openclaw(&args(&["connect", "openclaw"])));
        assert!(names_openclaw(&args(&["connect", "OpenClaw", "--monitor"])));
        assert!(names_openclaw(&args(&["connect", "--all"])));
        assert!(names_openclaw(&args(&["disconnect"])));
        assert!(!names_openclaw(&args(&["connect", "claude-code"])));
    }
}
