//! The first-run onboarding wizard's I/O half: live agent detection and a SIMPLE,
//! sequential, guided flow (one clear question at a time - never a checkbox grid a
//! non-expert selects wrong). It guards agents in DRY RUN by default (observes,
//! never blocks), then optionally wires alerts (any mix of channels) and an own-AI
//! second opinion. Wording lives in the pure `setup` module; the agent list +
//! connect logic in `agents` / `agents_ops` / `mcp_wire`; the notify + llm config
//! in their own modules. Excluded from the coverage floor like the other `_io`
//! adapters (pure interactive terminal I/O).

use std::io::IsTerminal;
use std::process::ExitCode;

use dialoguer::{theme::ColorfulTheme, Confirm, Input, MultiSelect, Password, Select};

use crate::agent_policy::{self, DesiredMode};
use crate::setup;

fn guard_bin() -> String {
    std::env::current_exe()
        .ok()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "innerwarden".to_string())
}

fn connect_setup_agents(
    home: &std::path::Path,
    agents: &[innerwarden_agent_guard::agents::AgentStatus],
    guard_bin: &str,
) -> Result<Vec<innerwarden_agent_guard::agents_ops::ConnectResult>, String> {
    agent_policy::with_lock(home, || {
        let mut results = Vec::with_capacity(agents.len());
        for agent in agents {
            // This is an explicit operator choice, so it also reverses a prior
            // disconnect exclusion. Keep policy intent and config mutation under
            // the same lock used by CLI commands and the background reconciler.
            agent_policy::include_agent(home, &agent.name)?;
            results.push(innerwarden_agent_guard::agents_ops::connect_one_result(
                home, agent, guard_bin, false, true,
            ));
        }
        Ok(results)
    })
}

/// `innerwarden setup` - the friendly first-run flow. Sequential yes/no questions,
/// each with a plain-language prompt; details are asked only after a "yes". Guards
/// in DRY RUN so nothing is ever blocked until the user runs `innerwarden enforce`.
/// With no terminal (piped `curl | sh`, CI) it prints the options + exact commands.
pub fn cmd(_rest: &[String]) -> ExitCode {
    let prog = crate::prog();

    if !std::io::stdin().is_terminal() {
        println!("{}", setup::noninteractive_summary(&prog));
        return ExitCode::SUCCESS;
    }

    let home = match innerwarden_agent_guard::hook::home_dir() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("{prog} setup: {e}");
            return ExitCode::from(2);
        }
    };
    let theme = ColorfulTheme::default();

    println!("\n  {} - AI-agent guardrail setup\n", crate::COMMUNITY_NAME);
    println!("  It screens actions from your AI agents and can flag (or later block)");
    println!(
        "  the dangerous ones. We'll set it up in DRY RUN first, so nothing is blocked yet.\n"
    );

    // ── 1. Guard agents (DRY RUN / monitor by default) ───────────────────────
    let detected = innerwarden_agent_guard::agents_ops::rows(&home);
    let agents: Vec<_> = detected
        .iter()
        .filter(|agent| agent.guardable())
        .cloned()
        .collect();
    let manual_only: Vec<_> = detected
        .iter()
        .filter(|agent| !agent.guardable())
        .map(|agent| agent.name.as_str())
        .collect();
    let bin = guard_bin();
    let mut configured_in_monitor = false;
    let mut offer_auto_connect = agents.is_empty();
    if detected.is_empty() {
        println!(
            "  No AI agent detected yet (looked for Claude Code, Cursor, Codex, Gemini, Goose,"
        );
        println!(
            "  Aider, OpenClaw, Hermes Agent). Install one and re-run `{prog} setup`, or guard later with"
        );
        println!("  `{prog} agents connect --all --monitor`.");
    } else if agents.is_empty() {
        println!("  Found for visibility: {}.", manual_only.join(", "));
        println!(
            "  None has a reviewed automatic integration yet; InnerWarden will not rewrite an unsupported config format."
        );
        println!(
            "  They remain detection-only in `{prog} agents` and the local dashboard; protection requires a manual integration."
        );
    } else {
        let names: Vec<String> = agents
            .iter()
            .map(|a| {
                let st = if !a.pids.is_empty() {
                    "running"
                } else if a.installed {
                    "installed"
                } else {
                    "detected"
                };
                format!("{} ({st})", a.name)
            })
            .collect();
        println!("  Found: {}", names.join(", "));
        if !manual_only.is_empty() {
            println!(
                "  Also visible (manual integration only): {}.",
                manual_only.join(", ")
            );
        }
        let one = agents.len() == 1;
        let guard = Confirm::with_theme(&theme)
            .with_prompt(format!(
                "  Guard {} in dry run (observes activity, blocks nothing)?",
                if one { "it" } else { "them all" }
            ))
            .default(true)
            .interact()
            .unwrap_or(false);
        if guard {
            offer_auto_connect = true;
            match connect_setup_agents(&home, &agents, &bin) {
                Ok(results) => {
                    for result in results {
                        configured_in_monitor |= result.configured();
                        println!("{}", result.line);
                    }
                }
                Err(error) => {
                    eprintln!("  Could not coordinate agent setup: {error}");
                }
            }
        } else {
            println!("  – skipped; guard later:  {prog} agents connect --all --monitor");
        }
    }

    let mut auto_connect_enabled = false;
    if offer_auto_connect {
        let automatic = Confirm::with_theme(&theme)
            .with_prompt(
                "  Automatically connect supported agents installed later in dry run while the dashboard is open?",
            )
            .default(true)
            .interact()
            .unwrap_or(false);
        match agent_policy::with_lock(&home, || {
            agent_policy::set_auto_connect(&home, automatic, DesiredMode::Monitor)
        }) {
            Ok(policy) => {
                auto_connect_enabled = policy.auto_connect;
                if automatic {
                    println!(
                        "  ✓ Automatic setup enabled; new connections and misplaced-only Claude hook repairs are monitor-only."
                    );
                    println!(
                        "    Recognized Claude hooks may be canonicalized; existing MCP wrappers and unknown, invalid, or excluded integrations stay unchanged."
                    );
                } else {
                    println!("  - automatic setup disabled; connect agents manually when needed.");
                }
            }
            Err(error) => eprintln!("  Could not save automatic setup preference: {error}"),
        }
    }

    // ── 2. Alerts (optional, any mix of channels) ────────────────────────────
    println!();
    let want_alerts = Confirm::with_theme(&theme)
        .with_prompt("  Get notified when a command is flagged? (or just watch the dashboard)")
        .default(false)
        .interact()
        .unwrap_or(false);
    if want_alerts {
        configure_alerts(&theme, &prog);
    }

    // ── 3. Second opinion / own AI model (optional - FEWER alerts) ───────────
    println!();
    if crate::second_opinion_io::is_configured() && crate::second_opinion_io::has_key() {
        println!("  Second opinion - already set (change:  {prog} llm set-key)");
    } else {
        let want_llm = Confirm::with_theme(&theme)
            .with_prompt(
                "  Add your own AI model to auto-decide the AMBIGUOUS commands? (fewer alerts reach you)",
            )
            .default(false)
            .interact()
            .unwrap_or(false);
        if want_llm {
            configure_second_opinion(&theme, &prog);
        }
    }

    // ── Done + how to leave dry run ──────────────────────────────────────────
    if configured_in_monitor {
        println!("\n  ✓ Setup done - integrations are configured for DRY RUN.");
        println!("    Restart those agents; activity will be recorded but not blocked.");
        println!("    Review captured hook, MCP and manual-check decisions:");
        println!("        {prog} dashboard  (or: {prog} graph)");
        println!("    Ready to actually block the dangerous ones:");
        println!("        {prog} enforce\n");
    } else {
        println!("\n  ✓ Setup finished - no agent integration was configured in this run.");
        println!("    Start safely later with:");
        println!("        {prog} agents connect --all --monitor\n");
    }
    if auto_connect_enabled {
        println!(
            "    Keep `{prog} dashboard` running to discover new supported agents every {} seconds.\n",
            agent_policy::RECONCILE_INTERVAL_SECS
        );
    }
    ExitCode::SUCCESS
}

/// Ask which alert channels to use (any mix) and collect the easy input for each.
/// Slack/Discord = paste a webhook URL; Telegram = bot token + chat id (with a
/// one-line how-to). Sends a test ping so the user SEES it works.
fn configure_alerts(theme: &ColorfulTheme, prog: &str) {
    if crate::notify_io::is_configured() {
        println!("  (you already have alerts - picking channels here ADDS to them)");
    }
    let channels: &[&str] = &["Telegram", "Slack", "Discord"];
    let picks = MultiSelect::with_theme(theme)
        .with_prompt("  Which channels?  (↑↓ move · SPACE to pick · ENTER to confirm - pick as many as you want)")
        .items(channels)
        .interact()
        .unwrap_or_default();
    if picks.is_empty() {
        println!("  – no channel picked; add later:  {prog} notify --slack-webhook <URL>");
        return;
    }

    let mut args: Vec<String> = Vec::new();
    let mut configured = 0usize;
    for &i in &picks {
        match channels[i] {
            "Telegram" => {
                println!(
                    "    Telegram - create a bot with @BotFather, copy its token, then get your chat id."
                );
                let token = Password::with_theme(theme)
                    .with_prompt("    Telegram bot token")
                    .allow_empty_password(true)
                    .interact()
                    .unwrap_or_default();
                if token.trim().is_empty() {
                    println!("    – no token; Telegram skipped.");
                    continue;
                }
                let chat: String = Input::with_theme(theme)
                    .with_prompt("    Telegram chat id")
                    .allow_empty(true)
                    .interact_text()
                    .unwrap_or_default();
                if chat.trim().is_empty() {
                    println!("    – no chat id; Telegram skipped.");
                    continue;
                }
                args.push("--telegram-token".into());
                args.push(token);
                args.push("--telegram-chat".into());
                args.push(chat);
                configured += 1;
            }
            "Slack" => {
                let url: String = Input::with_theme(theme)
                    .with_prompt("    Slack Incoming Webhook URL")
                    .allow_empty(true)
                    .interact_text()
                    .unwrap_or_default();
                if url.trim().is_empty() {
                    println!("    – no URL; Slack skipped.");
                    continue;
                }
                args.push("--slack-webhook".into());
                args.push(url);
                configured += 1;
            }
            "Discord" => {
                let url: String = Input::with_theme(theme)
                    .with_prompt("    Discord Webhook URL")
                    .allow_empty(true)
                    .interact_text()
                    .unwrap_or_default();
                if url.trim().is_empty() {
                    println!("    – no URL; Discord skipped.");
                    continue;
                }
                args.push("--discord-webhook".into());
                args.push(url);
                configured += 1;
            }
            _ => {}
        }
    }

    if configured == 0 {
        println!("  – nothing configured; add later:  {prog} notify --slack-webhook <URL>");
        return;
    }
    // Fire a test alert so the user immediately sees the channel(s) work.
    args.push("--test".into());
    let _ = crate::notify_io::cmd(&args);
    println!(
        "  ✓ Alerts on ({configured} channel{}); a test ping was sent.",
        if configured == 1 { "" } else { "s" }
    );
}

/// Prompt for an API key (HIDDEN) and store it 0600, returning the file path for
/// `api_key_file`. `None` when left blank or the write fails. Never echoes the key.
fn prompt_and_store_key(theme: &ColorfulTheme) -> Option<String> {
    let key = Password::with_theme(theme)
        .with_prompt("    Paste your API key (hidden; blank to add later)")
        .allow_empty_password(true)
        .interact()
        .unwrap_or_default();
    if key.trim().is_empty() {
        return None;
    }
    match crate::second_opinion_io::store_key(&key) {
        Ok(p) => Some(p.display().to_string()),
        Err(e) => {
            println!("    ! could not store the key: {e}");
            None
        }
    }
}

/// The fresh second-opinion setup: pick a provider by NAME (preset), confirm the
/// URL + model, paste the key, then VERIFY the endpoint actually answers so we
/// never claim "working" on a bad key/model. Persists a complete config so a normal
/// user never touches an env var. Interactive I/O only.
fn configure_second_opinion(theme: &ColorfulTheme, prog: &str) {
    use crate::second_opinion::{LlmConfig, PRESETS};

    let mut items: Vec<String> = PRESETS.iter().map(|p| p.label.to_string()).collect();
    items.push("Skip for now".to_string());
    let pick = Select::with_theme(theme)
        .with_prompt("    Which model provider?")
        .items(&items)
        .default(0)
        .interact()
        .unwrap_or(items.len() - 1);
    if pick >= PRESETS.len() {
        println!("    – skipped; set later:  {prog} llm set --url <URL> --model <M> && {prog} llm set-key");
        return;
    }
    let preset = &PRESETS[pick];

    // URL: use the preset's, or ask when it is deployment/endpoint-specific. Loop
    // until it's a real http(s) URL - this catches the #1 confusion where the user
    // pastes their API KEY into the URL box (as happened with the Azure preset).
    let url = if preset.url.is_empty() {
        let mut chosen = String::new();
        for _ in 0..3 {
            let input = Input::<String>::with_theme(theme)
                .with_prompt("    Endpoint URL - starts with https:// (the ADDRESS, NOT your key)")
                .allow_empty(true)
                .interact_text()
                .unwrap_or_default();
            let t = input.trim();
            if t.is_empty() {
                break; // user chose to skip
            }
            if crate::second_opinion::looks_like_url(t) {
                chosen = t.to_string();
                break;
            }
            println!("    ⚠ that isn't a URL (it must start with https://). If that was your API key, you'll paste it on the NEXT step.");
        }
        chosen
    } else {
        preset.url.to_string()
    };
    // Model: preset default, editable.
    let model = Input::<String>::with_theme(theme)
        .with_prompt("    Model / deployment name")
        .with_initial_text(preset.model)
        .allow_empty(true)
        .interact_text()
        .unwrap_or_else(|_| preset.model.to_string());

    // Never persist a broken config: require a real URL (so the key can never end
    // up in the `url` field) and a model.
    if !crate::second_opinion::looks_like_url(&url) || model.trim().is_empty() {
        println!("    – no valid https URL given; nothing saved. Re-run `{prog} setup` (tip: pick OpenAI to skip the URL step).");
        return;
    }

    // API key: paste it right here (hidden). Local endpoints (Ollama) need none.
    let api_key_file = if preset.needs_key {
        prompt_and_store_key(theme)
    } else {
        None
    };

    let cfg = LlmConfig {
        provider: preset.provider.to_string(),
        url,
        model,
        api_key_env: None,
        api_key_file,
        min_risk: None,
    };
    if let Err(e) = crate::second_opinion_io::write_config(&cfg) {
        println!("    ! could not save the llm config: {e}");
        return;
    }

    // A keyless local endpoint, or a key we just stored: VERIFY it actually works,
    // so we never tell the user "on" when the key/model/URL is wrong (silent fail).
    if cfg.api_key_file.is_some() || !preset.needs_key {
        print!("    checking the endpoint… ");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        match crate::second_opinion_io::verify_endpoint(&cfg) {
            Ok(()) => println!(
                "✓ working - second opinion is live ({} via {}).",
                cfg.model, cfg.provider
            ),
            Err(e) => println!(
                "\n    ⚠ saved, but the test call failed: {e}\n      fix it, then:  {prog} llm set-key   (or re-run {prog} setup)"
            ),
        }
    } else {
        println!("    second opinion - endpoint saved; add the key later:  {prog} llm set-key");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_setup_connect_clears_exclusion_and_wires_monitor_mode() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        std::fs::write(
            home.path().join(".cursor/mcp.json"),
            r#"{"mcpServers":{"local":{"command":"npx"}}}"#,
        )
        .unwrap();
        agent_policy::exclude_agent(home.path(), "cursor").unwrap();
        let cursor = innerwarden_agent_guard::agents_ops::rows(home.path())
            .into_iter()
            .find(|agent| agent.name == "cursor")
            .unwrap();

        let results = connect_setup_agents(home.path(), &[cursor], "/abs/innerwarden").unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].configured());
        assert!(agent_policy::load(home.path()).unwrap().excluded.is_empty());
        let config = std::fs::read_to_string(home.path().join(".cursor/mcp.json")).unwrap();
        assert!(config.contains("innerwarden"));
        assert!(config.contains("advisory"));
    }
}
