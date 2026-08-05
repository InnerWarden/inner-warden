//! `innerwarden dashboard` - a tiny local web UI over Community visibility.
//!
//! The UI is the canonical React app from `crates/dashboard-kit/web`, built to
//! static files and EMBEDDED by `innerwarden-dashboard-kit`, so there is no external file to ship and
//! nothing to install: `innerwarden dashboard` serves it on loopback and the browser
//! holds the UI (the process itself stays tiny). All the data logic lives in the
//! shared `innerwarden-graph` crate (`overview`, the graph model) which is fully
//! tested; this file is the thin HTTP adapter (routing + static serving) plus pure
//! helpers. HTTP handlers are read-only. When the operator explicitly enables
//! monitor-only agent discovery, an independent dashboard-owned worker may update
//! reviewed agent configs; it never runs as a side effect of a request.

use serde::Serialize;

const DEFAULT_BIND: &str = "127.0.0.1:8788";
const AGENT_REFRESH_SECS: u64 = 30;
const TOKEN_REFRESH_SECS: u64 = 300;

/// Map a request URL to the embedded asset path: `/` (and any unknown route) →
/// `index.html` (single-page app), otherwise the leading slash is stripped. Pure.
pub fn asset_path(url: &str) -> String {
    let path = url.split('?').next().unwrap_or("/").trim_start_matches('/');
    if path.is_empty() {
        "index.html".to_string()
    } else {
        path.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuardrailStatus {
    /// `not_configured` | `monitor` | `enforce` | `mixed` | `partial` | `unknown`.
    pub mode: String,
    /// Count of detected agent configurations that are currently wired through
    /// InnerWarden. We intentionally do not claim a live connection.
    pub guarded_agents: usize,
}

#[derive(Serialize)]
struct DashboardMeta<'a> {
    version: &'a str,
    exposed: bool,
    edition: &'a str,
    guardrail: &'a GuardrailStatus,
}

/// `/api/agents` contract version. Version 2 distinguishes executable presence
/// from non-authorizing discovery evidence and exposes the precise evidence
/// names instead of the former aggregate installation marker.
const AGENTS_SCHEMA_VERSION: u8 = 2;

#[derive(Serialize)]
struct AgentsPayload {
    schema_version: u8,
    generated_at_ms: u64,
    availability: &'static str,
    discovery_limited: bool,
    auto_connect: AutoConnectView,
    agents: Vec<AgentView>,
}

#[derive(Serialize)]
struct AutoConnectView {
    status: &'static str,
    enabled: Option<bool>,
    mode: Option<&'static str>,
    refresh_interval_secs: u64,
    watcher: crate::agent_policy::DashboardReconcilerStatus,
}

#[derive(Serialize)]
struct AgentView {
    id: String,
    display_name: String,
    installed: bool,
    running: Option<bool>,
    detected_by: Vec<&'static str>,
    guardrail: AgentGuardrailView,
    auto_connect_eligible: Option<bool>,
}

#[derive(Serialize)]
struct AgentGuardrailView {
    mode: String,
    mechanism: Option<&'static str>,
    setup_support: &'static str,
}

#[derive(Clone)]
struct AgentSnapshot {
    json: String,
    guardrail: GuardrailStatus,
    observed_at_ms: u64,
}

type SharedAgentSnapshot = std::sync::Arc<std::sync::RwLock<AgentSnapshot>>;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

fn display_agent_name(name: &str) -> String {
    match name {
        "claude-code" => "Claude Code".into(),
        "cursor" => "Cursor".into(),
        "codex" => "Codex".into(),
        "gemini" => "Gemini CLI".into(),
        "goose" => "Goose".into(),
        "aider" => "Aider".into(),
        "openclaw" => "OpenClaw".into(),
        "hermes" => "Hermes Agent".into(),
        other => other
            .split(['-', '_'])
            .filter(|part| !part.is_empty())
            .map(|part| {
                let mut chars = part.chars();
                chars
                    .next()
                    .map(|first| first.to_uppercase().collect::<String>() + chars.as_str())
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>()
            .join(" "),
    }
}

fn agent_mechanism(agent: &innerwarden_agent_guard::agents::AgentStatus) -> Option<&'static str> {
    if agent.hookable {
        Some("pretooluse_hook")
    } else if agent.mcp_json.is_some() || agent.mcp_toml.is_some() {
        Some("mcp_proxy")
    } else {
        None
    }
}

#[cfg(test)]
fn agents_json(
    home: &std::path::Path,
    rows: &[innerwarden_agent_guard::agents::AgentStatus],
) -> String {
    agents_json_with_status(home, rows, false, None)
}

fn agents_json_with_status(
    home: &std::path::Path,
    rows: &[innerwarden_agent_guard::agents::AgentStatus],
    discovery_limited: bool,
    watcher: Option<&crate::agent_policy::SharedDashboardReconcilerStatus>,
) -> String {
    let (policy, policy_available) = match crate::agent_policy::load(home) {
        Ok(policy) => (policy, true),
        Err(_) => (crate::agent_policy::AgentPolicy::default(), false),
    };
    let agents = rows
        .iter()
        .map(|agent| {
            let effectively_guarded =
                innerwarden_agent_guard::agents_ops::status_is_effectively_guarded(home, agent);
            let known = crate::agent_policy::is_reviewed_integration(agent);
            let detected_by = agent
                .evidence
                .iter()
                .map(|evidence| evidence.api_name())
                .collect();
            AgentView {
                id: agent.name.clone(),
                display_name: display_agent_name(&agent.name),
                installed: agent.installed,
                running: if cfg!(target_os = "linux") {
                    Some(!agent.pids.is_empty())
                } else {
                    None
                },
                detected_by,
                guardrail: AgentGuardrailView {
                    mode: if effectively_guarded {
                        agent_mode(home, agent).to_string()
                    } else {
                        "not_configured".into()
                    },
                    mechanism: agent_mechanism(agent),
                    setup_support: if known && agent.guardable() {
                        "automatic"
                    } else if agent.guardable() {
                        "manual"
                    } else {
                        "unsupported"
                    },
                },
                auto_connect_eligible: policy_available
                    .then(|| crate::agent_policy::is_auto_connect_candidate(home, agent, &policy)),
            }
        })
        .collect();
    serde_json::to_string(&AgentsPayload {
        schema_version: AGENTS_SCHEMA_VERSION,
        generated_at_ms: now_ms(),
        availability: "available",
        discovery_limited,
        auto_connect: AutoConnectView {
            status: if policy_available {
                "available"
            } else {
                "unavailable"
            },
            enabled: policy_available.then_some(policy.auto_connect),
            mode: policy_available.then_some(if policy.auto_connect {
                "monitor"
            } else {
                "disabled"
            }),
            refresh_interval_secs: crate::agent_policy::RECONCILE_INTERVAL_SECS,
            watcher: watcher
                .map(crate::agent_policy::read_dashboard_reconciler_status)
                .unwrap_or_else(crate::agent_policy::DashboardReconcilerStatus::unavailable),
        },
        agents,
    })
    .unwrap_or_else(|_| "{}".into())
}

fn agents_loading_json(
    watcher: Option<&crate::agent_policy::SharedDashboardReconcilerStatus>,
) -> String {
    serde_json::to_string(&AgentsPayload {
        schema_version: AGENTS_SCHEMA_VERSION,
        generated_at_ms: now_ms(),
        availability: "loading",
        discovery_limited: false,
        auto_connect: AutoConnectView {
            status: "unavailable",
            enabled: None,
            mode: None,
            refresh_interval_secs: crate::agent_policy::RECONCILE_INTERVAL_SECS,
            watcher: watcher
                .map(crate::agent_policy::read_dashboard_reconciler_status)
                .unwrap_or_else(crate::agent_policy::DashboardReconcilerStatus::unavailable),
        },
        agents: Vec::new(),
    })
    .unwrap_or_else(|_| "{}".into())
}

fn build_agent_snapshot(
    home: &std::path::Path,
    watcher: Option<&crate::agent_policy::SharedDashboardReconcilerStatus>,
) -> AgentSnapshot {
    let (rows, discovery_limited) =
        innerwarden_agent_guard::agents_ops::rows_with_discovery_status(home);
    AgentSnapshot {
        json: agents_json_with_status(home, &rows, discovery_limited, watcher),
        guardrail: guardrail_status_from_rows(home, &rows),
        observed_at_ms: now_ms(),
    }
}

fn spawn_agent_refresher(
    home: std::path::PathBuf,
    watcher: Option<crate::agent_policy::SharedDashboardReconcilerStatus>,
) -> Result<SharedAgentSnapshot, String> {
    let loading_json = agents_loading_json(watcher.as_ref());
    let shared = std::sync::Arc::new(std::sync::RwLock::new(AgentSnapshot {
        json: loading_json,
        guardrail: GuardrailStatus {
            mode: "unknown".into(),
            guarded_agents: 0,
        },
        observed_at_ms: now_ms(),
    }));
    let writer = std::sync::Arc::clone(&shared);
    std::thread::Builder::new()
        .name("iw-agent-visibility".into())
        .spawn(move || loop {
            let next = build_agent_snapshot(&home, watcher.as_ref());
            match writer.write() {
                Ok(mut snapshot) => *snapshot = next,
                Err(poisoned) => *poisoned.into_inner() = next,
            }
            std::thread::sleep(std::time::Duration::from_secs(AGENT_REFRESH_SECS));
        })
        .map_err(|error| format!("starting agent visibility refresh: {error}"))?;
    Ok(shared)
}

fn read_agent_snapshot(shared: &SharedAgentSnapshot) -> AgentSnapshot {
    match shared.read() {
        Ok(snapshot) => snapshot.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

fn agent_payload_with_live_watcher(
    snapshot_json: String,
    watcher: Option<&crate::agent_policy::SharedDashboardReconcilerStatus>,
) -> String {
    let Some(watcher) = watcher else {
        return snapshot_json;
    };
    let Ok(mut payload) = serde_json::from_str::<serde_json::Value>(&snapshot_json) else {
        return snapshot_json;
    };
    let Some(auto_connect) = payload
        .get_mut("auto_connect")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return snapshot_json;
    };
    let live = crate::agent_policy::read_dashboard_reconciler_status(watcher);
    let Ok(status) = serde_json::to_value(&live) else {
        return snapshot_json;
    };
    if live.policy_available {
        auto_connect.insert("status".into(), serde_json::json!("available"));
        auto_connect.insert("enabled".into(), serde_json::json!(live.policy_enabled));
        auto_connect.insert("mode".into(), serde_json::json!(live.effective_policy_mode));
    } else {
        auto_connect.insert("status".into(), serde_json::json!("unavailable"));
        auto_connect.insert("enabled".into(), serde_json::Value::Null);
        auto_connect.insert("mode".into(), serde_json::Value::Null);
    }
    auto_connect.insert("watcher".into(), status);
    serde_json::to_string(&payload).unwrap_or(snapshot_json)
}

fn token_intelligence_json(
    shared: &innerwarden_dashboard_kit::token_usage::SharedTokenIntelligence,
) -> String {
    let report = match shared.read() {
        Ok(report) => report,
        Err(poisoned) => poisoned.into_inner(),
    };
    serde_json::to_string(&*report).unwrap_or_else(|_| "{}".into())
}

fn dashboard_contract_mode(
    status: &GuardrailStatus,
) -> innerwarden_dashboard_kit::contract::EffectiveMode {
    use innerwarden_dashboard_kit::contract::EffectiveMode;
    match status.mode.as_str() {
        "monitor" => EffectiveMode::Observe,
        "enforce" => EffectiveMode::Enforce,
        "mixed" | "partial" => EffectiveMode::Mixed,
        "not_configured" => EffectiveMode::Disabled,
        _ => EffectiveMode::Unknown,
    }
}

fn agent_contract_observation(
    snapshot: Option<&AgentSnapshot>,
) -> (
    innerwarden_dashboard_kit::contract::Availability,
    Option<u64>,
) {
    use innerwarden_dashboard_kit::contract::Availability;
    let Some(snapshot) = snapshot else {
        return (Availability::Unavailable, None);
    };
    let availability = match serde_json::from_str::<serde_json::Value>(&snapshot.json)
        .ok()
        .and_then(|payload| payload.get("availability")?.as_str().map(str::to_owned))
        .as_deref()
    {
        Some("available") => Availability::Available,
        Some("loading") => Availability::Loading,
        Some("error") => Availability::Degraded,
        _ => Availability::Unknown,
    };
    (availability, Some(snapshot.observed_at_ms))
}

fn token_contract_observation(
    shared: Option<&innerwarden_dashboard_kit::token_usage::SharedTokenIntelligence>,
) -> (
    innerwarden_dashboard_kit::contract::Availability,
    Option<u64>,
) {
    use innerwarden_dashboard_kit::contract::Availability;
    use innerwarden_dashboard_kit::token_usage::ReportAvailability;
    let Some(shared) = shared else {
        return (Availability::Unavailable, None);
    };
    let report = match shared.read() {
        Ok(report) => report,
        Err(poisoned) => poisoned.into_inner(),
    };
    let availability = match report.availability {
        ReportAvailability::Loading => Availability::Loading,
        ReportAvailability::Partial | ReportAvailability::NoData => Availability::Available,
        ReportAvailability::Error => Availability::Degraded,
    };
    (availability, Some(report.generated_at_ms))
}

fn community_projection_input(
    exposed: bool,
    agent: Option<&AgentSnapshot>,
    tokens: Option<&innerwarden_dashboard_kit::token_usage::SharedTokenIntelligence>,
) -> innerwarden_dashboard_kit::community::CommunityProjectionInput {
    use innerwarden_dashboard_kit::contract::Availability;
    let guardrail = agent
        .map(|snapshot| snapshot.guardrail.clone())
        .unwrap_or(GuardrailStatus {
            mode: "unknown".into(),
            guarded_agents: 0,
        });
    let (discovery_availability, discovery_observed_at_ms) = agent_contract_observation(agent);
    let (token_availability, token_observed_at_ms) = token_contract_observation(tokens);
    let generated_at_ms = now_ms();
    innerwarden_dashboard_kit::community::CommunityProjectionInput {
        generated_at: innerwarden_dashboard_kit::community::now_rfc3339(),
        generated_at_ms,
        product_version: env!("CARGO_PKG_VERSION").into(),
        platform_os: std::env::consts::OS.into(),
        platform_architecture: std::env::consts::ARCH.into(),
        exposed,
        configured_guardrail_mode: dashboard_contract_mode(&guardrail),
        guarded_agents: guardrail.guarded_agents,
        discovery_availability,
        discovery_observed_at_ms,
        discovery_freshness_budget_seconds: AGENT_REFRESH_SECS * 2 + 5,
        token_availability,
        token_observed_at_ms,
        token_freshness_budget_seconds: TOKEN_REFRESH_SECS * 2 + 60,
        // Graph validity is evaluated by each bounded graph route. Bootstrap
        // does not re-read the full graph on every five-second poll.
        local_record_availability: Availability::Unknown,
        local_record_observed_at_ms: None,
        local_record_freshness_budget_seconds: 30,
    }
}

fn agent_mode(
    home: &std::path::Path,
    agent: &innerwarden_agent_guard::agents::AgentStatus,
) -> &'static str {
    if agent.hookable {
        let path = home.join(".claude/settings.json");
        return innerwarden_agent_guard::file_update::read_config_no_symlinks(home, &path)
            .ok()
            .flatten()
            .and_then(|body| serde_json::from_slice::<serde_json::Value>(&body).ok())
            .map(|settings| hook_mode(&settings))
            .unwrap_or("unknown");
    }
    if let Some(rel) = &agent.mcp_json {
        let path = home.join(rel);
        return innerwarden_agent_guard::file_update::read_config_no_symlinks(home, &path)
            .ok()
            .flatten()
            .and_then(|body| serde_json::from_slice::<serde_json::Value>(&body).ok())
            .map(|config| {
                let mode = innerwarden_agent_guard::mcp_wire::guarded_mode(&config);
                if !innerwarden_agent_guard::mcp_wire::is_guarded(&config) {
                    return if mode.is_some() { "partial" } else { "unknown" };
                }
                match mode {
                    Some(innerwarden_agent_guard::mcp_wire::WiringMode::Monitor) => "monitor",
                    Some(innerwarden_agent_guard::mcp_wire::WiringMode::Enforce) => "enforce",
                    Some(innerwarden_agent_guard::mcp_wire::WiringMode::Mixed) => "mixed",
                    None => "unknown",
                }
            })
            .unwrap_or("unknown");
    }
    if let Some(rel) = &agent.mcp_toml {
        let path = home.join(rel);
        return innerwarden_agent_guard::file_update::read_config_no_symlinks(home, &path)
            .ok()
            .flatten()
            .and_then(|body| {
                let body = std::str::from_utf8(&body).ok()?;
                body.parse().ok()
            })
            .map(|config| {
                let mode = innerwarden_agent_guard::mcp_wire_toml::guarded_mode_toml(&config);
                if !innerwarden_agent_guard::mcp_wire_toml::is_guarded_toml(&config) {
                    return if mode.is_some() { "partial" } else { "unknown" };
                }
                match mode {
                    Some(innerwarden_agent_guard::mcp_wire_toml::WiringMode::Monitor) => "monitor",
                    Some(innerwarden_agent_guard::mcp_wire_toml::WiringMode::Enforce) => "enforce",
                    Some(innerwarden_agent_guard::mcp_wire_toml::WiringMode::Mixed) => "mixed",
                    None => "unknown",
                }
            })
            .unwrap_or("unknown");
    }
    "unknown"
}

fn guardrail_status_from_rows(
    home: &std::path::Path,
    rows: &[innerwarden_agent_guard::agents::AgentStatus],
) -> GuardrailStatus {
    let guarded: Vec<_> = rows
        .iter()
        .filter(|agent| {
            agent.guardable()
                && innerwarden_agent_guard::agents_ops::status_is_effectively_guarded(home, agent)
        })
        .collect();
    if guarded.is_empty() {
        return GuardrailStatus {
            mode: "not_configured".into(),
            guarded_agents: 0,
        };
    }

    let modes: Vec<&str> = guarded
        .iter()
        .map(|agent| agent_mode(home, agent))
        .collect();
    GuardrailStatus {
        mode: aggregate_modes(&modes).into(),
        guarded_agents: guarded.len(),
    }
}

/// Report only exact InnerWarden hooks effective under `PreToolUse:Bash`.
fn hook_mode(settings: &serde_json::Value) -> &'static str {
    match innerwarden_agent_guard::hook::effective_iwguard_hook_mode(settings) {
        Some(innerwarden_agent_guard::hook::EffectiveHookMode::Monitor) => "monitor",
        Some(innerwarden_agent_guard::hook::EffectiveHookMode::Enforce) => "enforce",
        Some(innerwarden_agent_guard::hook::EffectiveHookMode::Mixed) => "mixed",
        None => "unknown",
    }
}

fn aggregate_modes(modes: &[&str]) -> &'static str {
    if modes.is_empty() {
        return "not_configured";
    }
    if modes.contains(&"unknown") {
        return "unknown";
    }
    if modes.contains(&"partial") {
        return "partial";
    }
    let monitor = modes.iter().any(|m| *m == "monitor" || *m == "mixed");
    let enforce = modes.iter().any(|m| *m == "enforce" || *m == "mixed");
    match (monitor, enforce) {
        (true, true) => "mixed",
        (true, false) => "monitor",
        (false, true) => "enforce",
        (false, false) => "unknown",
    }
}

fn meta_json_with_status(exposed: bool, status: &GuardrailStatus) -> String {
    serde_json::to_string(&DashboardMeta {
        version: env!("CARGO_PKG_VERSION"),
        exposed,
        edition: "community",
        guardrail: status,
    })
    .unwrap_or_else(|_| "{}".into())
}

/// True when `bind` targets loopback (safe: not reachable off-host). Anything else
/// publishes the read-only UI (command history + graph) to the network, and the
/// dashboard has NO auth/TLS, so a non-loopback bind must be an explicit, informed
/// opt-in (`--expose`). Pure/tested.
pub fn is_loopback_bind(bind: &str) -> bool {
    endpoint_is_loopback(bind)
}

fn endpoint_is_loopback(endpoint: &str) -> bool {
    let endpoint = endpoint.trim();
    if endpoint.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Some((host, port)) = endpoint.rsplit_once(':') {
        if host.eq_ignore_ascii_case("localhost") && port.parse::<u16>().is_ok() {
            return true;
        }
    }
    endpoint
        .parse::<std::net::SocketAddr>()
        .map(|address| address.ip().is_loopback())
        .or_else(|_| {
            endpoint
                .parse::<std::net::IpAddr>()
                .map(|address| address.is_loopback())
        })
        .unwrap_or(false)
}

fn request_host_is_allowed(request: &tiny_http::Request, exposed: bool) -> bool {
    let host = request
        .headers()
        .iter()
        .find(|header| header.field.equiv("Host"))
        .map(|header| header.value.as_str());
    host_header_is_allowed(host, exposed)
}

fn host_header_is_allowed(host: Option<&str>, exposed: bool) -> bool {
    exposed || host.is_some_and(endpoint_is_loopback)
}

/// Guess a Content-Type from a file extension (enough for a Vite bundle). Pure.
pub fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("woff2") => "font/woff2",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        _ => "application/octet-stream",
    }
}

/// `innerwarden dashboard [--bind IP:PORT]` - serve local visibility + read-only APIs.
pub fn cmd(rest: &[String]) -> std::process::ExitCode {
    let mut bind = DEFAULT_BIND.to_string();
    let mut expose = false;
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--bind" => {
                if let Some(v) = it.next() {
                    bind = v.clone();
                }
            }
            "--expose" => expose = true,
            "--help" | "-h" => {
                println!("innerwarden dashboard [--bind IP:PORT] [--expose]");
                println!("  local UI with read-only APIs (default {DEFAULT_BIND}).");
                println!("  an opt-in monitor-only worker may connect reviewed agents in the background.");
                println!(
                    "  --expose: allow a NON-loopback bind. The dashboard has NO auth/TLS, so"
                );
                println!("            this publishes decisions, detected agents, modes and token counters.");
                return std::process::ExitCode::SUCCESS;
            }
            _ => {}
        }
    }

    // Refuse a non-loopback bind unless the user explicitly opted in: the UI is
    // unauthenticated + unencrypted, so binding it to the network by accident would
    // publish the command history + raw graph to anyone who can reach the host.
    let exposed = !is_loopback_bind(&bind);
    if exposed && !expose {
        eprintln!(
            "innerwarden dashboard: refusing to bind {bind} - it is NOT loopback, and the dashboard has NO authentication or TLS.\n  This would publish decisions, detected agents, guard modes and token counters. If you really mean to, add --expose."
        );
        return std::process::ExitCode::from(2);
    }
    if exposed {
        eprintln!(
            "⚠  innerwarden dashboard: EXPOSED on {bind} with NO auth/TLS - anyone who can reach this host can read decisions, detected agents, guard modes and token counters."
        );
    }

    let server = match tiny_http::Server::http(bind.as_str()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("innerwarden dashboard: failed to bind {bind}: {e}");
            return std::process::ExitCode::from(1);
        }
    };

    // Configuration reconciliation is deliberately dashboard-owned and happens
    // outside HTTP handlers. GET requests remain read-only even while the
    // opt-in watcher discovers newly-installed agents in the background.
    let home = innerwarden_agent_guard::hook::home_dir().ok();
    let token_intelligence = home.as_ref().map(|home| {
        innerwarden_dashboard_kit::token_usage::spawn_refresher(
            home.clone(),
            std::time::Duration::from_secs(TOKEN_REFRESH_SECS),
        )
    });
    // Keep the handle alive for exactly the server lifetime. Dropping it stops
    // and joins the watcher; merely spawning then discarding the handle would
    // make automatic setup appear present while the worker is already stopped.
    let dashboard_reconciler = home.as_ref().and_then(|home| {
        let guard_bin = innerwarden_agent_guard::agents_ops::guard_bin();
        match crate::agent_policy::spawn_dashboard_reconciler(home.clone(), guard_bin) {
            Ok(reconciler) => Some(reconciler),
            Err(error) => {
                eprintln!("innerwarden dashboard: {error}");
                None
            }
        }
    });
    let watcher_status = dashboard_reconciler
        .as_ref()
        .map(crate::agent_policy::DashboardReconciler::status);
    // Agent discovery and config inspection are bounded background work. API
    // polling reads this snapshot, so one large home cannot block the
    // single-threaded HTTP loop or multiply scans across browser tabs.
    let agent_snapshot =
        home.clone().and_then(
            |home| match spawn_agent_refresher(home, watcher_status.clone()) {
                Ok(snapshot) => Some(snapshot),
                Err(error) => {
                    eprintln!("innerwarden dashboard: {error}");
                    None
                }
            },
        );
    let url = format!("http://{bind}");
    eprintln!("innerwarden dashboard: serving on {url}  (read-only API; Ctrl-C to stop)");

    for request in server.incoming_requests() {
        // A loopback socket alone is not a DNS-rebinding boundary. Browsers send
        // the attacker's hostname after rebinding it to 127.0.0.1, so reject any
        // non-literal-loopback Host unless the operator explicitly used --expose.
        if !request_host_is_allowed(&request, exposed) {
            let _ = request.respond(
                json_response(
                    serde_json::json!({"error": "dashboard Host is not allowed"}).to_string(),
                )
                .with_status_code(403),
            );
            continue;
        }
        let full = request.url().to_string();
        let path = full.split('?').next().unwrap_or("/").to_string();
        let query = full
            .split_once('?')
            .map(|(_, q)| q.to_string())
            .unwrap_or_default();
        if !api_method_is_allowed(&path, request.method()) {
            let _ = request.respond(method_not_allowed_response());
            continue;
        }
        let _ = match path.as_str() {
            "/api/dashboard/v1/bootstrap" => {
                let snapshot = agent_snapshot.as_ref().map(read_agent_snapshot);
                let input = community_projection_input(
                    exposed,
                    snapshot.as_ref(),
                    token_intelligence.as_ref(),
                );
                let body = serde_json::to_string(
                    &innerwarden_dashboard_kit::community::build_bootstrap(&input),
                )
                .unwrap_or_else(|_| "{}".into());
                request.respond(json_response(body))
            }
            "/api/dashboard/v1/posture" => {
                let snapshot = agent_snapshot.as_ref().map(read_agent_snapshot);
                let input = community_projection_input(
                    exposed,
                    snapshot.as_ref(),
                    token_intelligence.as_ref(),
                );
                let body = serde_json::to_string(
                    &innerwarden_dashboard_kit::community::build_posture(&input),
                )
                .unwrap_or_else(|_| "{}".into());
                request.respond(json_response(body))
            }
            // Additive, and deliberately its own route rather than a field on a
            // versioned projection: a dashboard that renders a stale record must
            // be able to say WHY it is stale without a schema bump. Absent an
            // outage the payload is `{"recording":true}` and nothing renders.
            "/api/guard/record-health" => {
                let body = match graph_io::current_outage() {
                    None => serde_json::json!({ "recording": true }),
                    Some(outage) => serde_json::json!({
                        "recording": false,
                        "code": outage.code,
                        "since_unix": outage.since_unix,
                        "seconds": outage.seconds(),
                        "lost_actions": outage.lost,
                        "summary": outage.summary(),
                    }),
                };
                request.respond(json_response(body.to_string()))
            }
            "/api/overview" | "/api/guard/overview" => match graph_io::load_graph_checked() {
                Ok(graph) => {
                    let body =
                        serde_json::to_string(&graph.overview(20)).unwrap_or_else(|_| "{}".into());
                    request.respond(json_response(body))
                }
                Err(error) => {
                    log_graph_unreadable(&error);
                    request.respond(graph_unreadable_response())
                }
            },
            "/api/cases" => {
                let g = match graph_io::load_graph_checked() {
                    Ok(graph) => graph,
                    Err(error) => {
                        log_graph_unreadable(&error);
                        let _ = request.respond(graph_unreadable_response());
                        continue;
                    }
                };
                let session = query_param(&query, "session");
                let verdict = query_param(&query, "verdict");
                let q = query_param(&query, "q");
                let offset = query_param(&query, "offset")
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(0);
                let limit = query_param(&query, "limit")
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(20)
                    .clamp(1, 100);
                let page = g.cases_page(
                    session.as_deref(),
                    verdict.as_deref(),
                    q.as_deref(),
                    offset,
                    limit,
                );
                let body = serde_json::to_string(&page).unwrap_or_else(|_| "{}".into());
                request.respond(json_response(body))
            }
            "/api/graph" => match graph_io::load_graph_checked() {
                Ok(graph) => request.respond(json_response(graph.to_json())),
                Err(error) => {
                    log_graph_unreadable(&error);
                    request.respond(graph_unreadable_response())
                }
            },
            "/api/meta" | "/api/guard/meta" => match agent_snapshot.as_ref() {
                Some(shared) => {
                    let snapshot = read_agent_snapshot(shared);
                    request.respond(json_response(meta_json_with_status(
                        exposed,
                        &snapshot.guardrail,
                    )))
                }
                None => request.respond(json_response(meta_json_with_status(
                    exposed,
                    &GuardrailStatus {
                        mode: "unknown".into(),
                        guarded_agents: 0,
                    },
                ))),
            },
            "/api/agents" | "/api/guard/agents" => match agent_snapshot.as_ref() {
                Some(shared) => {
                    let snapshot = read_agent_snapshot(shared);
                    request.respond(json_response(agent_payload_with_live_watcher(
                        snapshot.json,
                        watcher_status.as_ref(),
                    )))
                }
                None => request.respond(json_error_response(503, "user home is unavailable")),
            },
            "/api/token-intelligence" | "/api/guard/token-intelligence" => {
                match token_intelligence.as_ref() {
                    Some(shared) => request.respond(json_response(token_intelligence_json(shared))),
                    None => request.respond(json_error_response(503, "user home is unavailable")),
                }
            }
            other => serve_asset(request, other),
        };
    }
    std::process::ExitCode::SUCCESS
}

/// Extract a query-string parameter (`k=v&k2=v2`), with minimal `+`/`%XX`
/// decoding, or `None` when absent/empty. Pure/tested.
pub fn query_param(query: &str, key: &str) -> Option<String> {
    query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| decode(v))
        .filter(|s| !s.is_empty())
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn decode(s: &str) -> String {
    let s = s.replace('+', " ");
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        // Decode `%XX` from the RAW BYTES (never a str slice: a `%` followed by
        // the start of a multi-byte UTF-8 char would make `&s[i+1..i+3]` land on a
        // non-char-boundary and PANIC - a single crafted `?q=%€` would crash the
        // whole single-threaded dashboard).
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex_nibble(b[i + 1]), hex_nibble(b[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

use crate::graph_io;

fn json_response(body: String) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    let content_type =
        tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
            .expect("static header");
    let cache_control = tiny_http::Header::from_bytes(&b"Cache-Control"[..], &b"no-store"[..])
        .expect("static header");
    let nosniff = tiny_http::Header::from_bytes(&b"X-Content-Type-Options"[..], &b"nosniff"[..])
        .expect("static header");
    tiny_http::Response::from_string(body)
        .with_header(content_type)
        .with_header(cache_control)
        .with_header(nosniff)
}

fn json_error_response(status: u16, error: &str) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    let body = serde_json::json!({"error": error}).to_string();
    json_response(body).with_status_code(status)
}

fn log_graph_unreadable(error: &graph_io::GraphLoadError) {
    eprintln!("innerwarden dashboard: local decision record unavailable ({error})");
}

fn graph_unreadable_response() -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    json_response(
        serde_json::json!({
            "error": "graph_unreadable",
            "message": "Local decision record is temporarily unavailable."
        })
        .to_string(),
    )
    .with_status_code(503)
}

fn api_method_is_allowed(path: &str, method: &tiny_http::Method) -> bool {
    !path.starts_with("/api/") || method == &tiny_http::Method::Get
}

fn method_not_allowed_response() -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    let allow = tiny_http::Header::from_bytes(&b"Allow"[..], &b"GET"[..]).expect("static header");
    json_response(serde_json::json!({"error": "method not allowed"}).to_string())
        .with_status_code(405)
        .with_header(allow)
}

/// True when the last path segment has a file extension (e.g. `.js`, `.css`) - so
/// it names an ASSET, not a client-side SPA route. Pure/tested.
pub fn has_extension(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .map(|seg| seg.contains('.'))
        .unwrap_or(false)
}

fn respond_404_json(request: tiny_http::Request) -> std::io::Result<()> {
    let header = tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
        .expect("static header");
    request.respond(
        tiny_http::Response::from_string("{\"error\":\"not found\"}")
            .with_status_code(404)
            .with_header(header),
    )
}

fn serve_asset(request: tiny_http::Request, url: &str) -> std::io::Result<()> {
    // An unknown /api/* route is a real 404 - never fall back to the SPA HTML (that
    // returned index.html with a 200 + wrong MIME for missing API routes).
    if url.starts_with("/api/") {
        return respond_404_json(request);
    }
    let path = asset_path(url);
    if let Some(file) = innerwarden_dashboard_kit::assets::get(&path) {
        // An exact asset: serve it with the MIME derived from ITS extension.
        let header =
            tiny_http::Header::from_bytes(&b"Content-Type"[..], content_type(&path).as_bytes())
                .expect("static header");
        return request
            .respond(tiny_http::Response::from_data(file.into_owned()).with_header(header));
    }
    if has_extension(&path) {
        // A missing asset (has an extension) is a 404 - do NOT return HTML with a
        // JavaScript/CSS MIME (a broken script tag was silently served as index.html).
        return request
            .respond(tiny_http::Response::from_string("not found").with_status_code(404));
    }
    // An extension-less path is a client-side SPA route → serve index.html as HTML.
    match innerwarden_dashboard_kit::assets::get("index.html") {
        Some(file) => {
            let header = tiny_http::Header::from_bytes(
                &b"Content-Type"[..],
                &b"text/html; charset=utf-8"[..],
            )
            .expect("static header");
            request.respond(tiny_http::Response::from_data(file.into_owned()).with_header(header))
        }
        None => {
            request.respond(tiny_http::Response::from_string("not found").with_status_code(404))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_path_maps_root_and_strips_slash() {
        assert_eq!(asset_path("/"), "index.html");
        assert_eq!(asset_path(""), "index.html");
        assert_eq!(asset_path("/assets/index-abc.js"), "assets/index-abc.js");
        assert_eq!(asset_path("/assets/x.css?v=1"), "assets/x.css");
    }

    #[test]
    fn query_param_parses_decodes_and_ignores_empty() {
        let q = "verdict=deny&q=rm+%2Frf&offset=20&session=agent-1";
        assert_eq!(query_param(q, "verdict").as_deref(), Some("deny"));
        assert_eq!(query_param(q, "q").as_deref(), Some("rm /rf"));
        assert_eq!(query_param(q, "offset").as_deref(), Some("20"));
        assert_eq!(query_param(q, "session").as_deref(), Some("agent-1"));
        assert_eq!(query_param(q, "missing"), None);
        assert_eq!(query_param("q=", "q"), None, "empty value is None");
        assert_eq!(query_param("", "q"), None);
    }

    #[test]
    fn decode_never_panics_on_percent_before_multibyte_utf8() {
        // A `%` immediately followed by the start of a multi-byte UTF-8 char used
        // to panic (str-slice on a non-char-boundary) - a single `?q=%€` request
        // could crash the whole dashboard. Now it is decoded byte-wise: the `%` is
        // kept verbatim (no valid hex pair follows) and nothing panics.
        assert_eq!(decode("%\u{20AC}"), "%\u{20AC}"); // %€ (3-byte)
        assert_eq!(decode("%\u{1F600}"), "%\u{1F600}"); // %😀 (4-byte)
        assert_eq!(
            query_param("q=%\u{20AC}", "q").as_deref(),
            Some("%\u{20AC}")
        );
        // a genuine escape still decodes
        assert_eq!(decode("rm%20%2Frf"), "rm /rf");
    }

    #[test]
    fn content_type_by_extension() {
        assert_eq!(content_type("index.html"), "text/html; charset=utf-8");
        assert_eq!(
            content_type("assets/a.js"),
            "application/javascript; charset=utf-8"
        );
        assert_eq!(content_type("assets/a.css"), "text/css; charset=utf-8");
        assert_eq!(content_type("x.unknown"), "application/octet-stream");
    }

    #[test]
    fn dashboard_api_is_get_only() {
        assert!(api_method_is_allowed(
            "/api/dashboard/v1/bootstrap",
            &tiny_http::Method::Get
        ));
        assert!(!api_method_is_allowed(
            "/api/dashboard/v1/bootstrap",
            &tiny_http::Method::Post
        ));
        assert!(!api_method_is_allowed(
            "/api/agents",
            &tiny_http::Method::Put
        ));
        assert!(api_method_is_allowed("/posture", &tiny_http::Method::Post));
    }

    #[test]
    fn meta_json_carries_the_version_and_exposed_flag() {
        let status = GuardrailStatus {
            mode: "monitor".into(),
            guarded_agents: 2,
        };
        let m = meta_json_with_status(false, &status);
        assert!(m.contains("\"version\""));
        assert!(m.contains(env!("CARGO_PKG_VERSION")));
        let v: serde_json::Value = serde_json::from_str(&m).unwrap();
        assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(v["exposed"], false);
        assert_eq!(v["edition"], "community");
        assert_eq!(v["guardrail"]["mode"], "monitor");
        assert_eq!(v["guardrail"]["guarded_agents"], 2);
        let e: serde_json::Value =
            serde_json::from_str(&meta_json_with_status(true, &status)).unwrap();
        assert_eq!(e["exposed"], true);
    }

    #[test]
    fn hook_mode_is_conservative_and_detects_duplicate_modes() {
        let settings = serde_json::json!({
            "hooks": {"PreToolUse": [
                {"matcher": "Bash", "hooks": [
                    {"command": "\"/opt/innerwarden\" hook --monitor"}
                ]}
            ]}
        });
        assert_eq!(hook_mode(&settings), "monitor");

        let mixed = serde_json::json!({
            "hooks": {"PreToolUse": [
                {"matcher": "Bash", "hooks": [
                    {"command": "\"/opt/innerwarden\" hook --monitor"}
                ]},
                {"matcher": "Bash", "hooks": [
                    {"command": "\"/opt/innerwarden\" hook"}
                ]}
            ]}
        });
        assert_eq!(hook_mode(&mixed), "mixed");

        let misplaced = serde_json::json!({
            "hooks": {"PreToolUse": [
                {"matcher": "Write", "hooks": [
                    {"command": "\"/opt/innerwarden\" hook --block-review"}
                ]}
            ]}
        });
        assert_eq!(hook_mode(&misplaced), "unknown");
        for matcher in [None, Some(""), Some("*"), Some("Bash|Write")] {
            let mut entry = serde_json::json!({
                "hooks": [{"command": "\"/opt/innerwarden\" hook --block-review"}]
            });
            if let Some(matcher) = matcher {
                entry["matcher"] = serde_json::json!(matcher);
            }
            let effective = serde_json::json!({"hooks": {"PreToolUse": [entry]}});
            assert_eq!(
                hook_mode(&effective),
                "enforce",
                "matcher {matcher:?} must cover Bash"
            );
        }
        let ambiguous_regex = serde_json::json!({
            "hooks": {"PreToolUse": [{
                "matcher": "^Bash$",
                "hooks": [{"command": "\"/opt/innerwarden\" hook --block-review"}]
            }]}
        });
        assert_eq!(hook_mode(&ambiguous_regex), "unknown");
        let version_dependent_list = serde_json::json!({
            "hooks": {"PreToolUse": [{
                "matcher": "Write, Bash",
                "hooks": [{"command": "\"/opt/innerwarden\" hook --block-review"}]
            }]}
        });
        assert_eq!(hook_mode(&version_dependent_list), "unknown");
        assert_eq!(hook_mode(&serde_json::json!({})), "unknown");
    }

    #[test]
    fn aggregate_mode_never_turns_ambiguity_into_enforcement() {
        assert_eq!(aggregate_modes(&[]), "not_configured");
        assert_eq!(aggregate_modes(&["monitor"]), "monitor");
        assert_eq!(aggregate_modes(&["enforce", "enforce"]), "enforce");
        assert_eq!(aggregate_modes(&["monitor", "enforce"]), "mixed");
        assert_eq!(aggregate_modes(&["monitor", "partial"]), "partial");
        assert_eq!(aggregate_modes(&["enforce", "unknown"]), "unknown");
    }

    #[test]
    fn dashboard_contract_mode_treats_configuration_as_desired_not_verified() {
        use innerwarden_dashboard_kit::contract::EffectiveMode;
        let status = |mode: &str| GuardrailStatus {
            mode: mode.into(),
            guarded_agents: 1,
        };
        assert_eq!(
            dashboard_contract_mode(&status("monitor")),
            EffectiveMode::Observe
        );
        assert_eq!(
            dashboard_contract_mode(&status("enforce")),
            EffectiveMode::Enforce
        );
        assert_eq!(
            dashboard_contract_mode(&status("mixed")),
            EffectiveMode::Mixed
        );
        assert_eq!(
            dashboard_contract_mode(&status("partial")),
            EffectiveMode::Mixed
        );
        assert_eq!(
            dashboard_contract_mode(&status("not_configured")),
            EffectiveMode::Disabled
        );
        assert_eq!(
            dashboard_contract_mode(&status("surprise")),
            EffectiveMode::Unknown
        );
    }

    #[test]
    fn v1_projection_uses_snapshot_time_and_never_promotes_configured_enforce() {
        use innerwarden_dashboard_kit::contract::{
            Availability, EffectiveMode, FreshnessState, StageAnswer,
        };
        let snapshot = AgentSnapshot {
            json: serde_json::json!({"availability": "available"}).to_string(),
            guardrail: GuardrailStatus {
                mode: "enforce".into(),
                guarded_agents: 1,
            },
            observed_at_ms: 1,
        };
        let input = community_projection_input(false, Some(&snapshot), None);
        let bootstrap = innerwarden_dashboard_kit::community::build_bootstrap(&input);
        let guardrail = bootstrap
            .capabilities
            .iter()
            .find(|capability| capability.id == "community.agent_guardrails")
            .unwrap();
        assert_eq!(guardrail.desired_mode, EffectiveMode::Enforce);
        assert_eq!(guardrail.effective_mode, EffectiveMode::Unknown);
        assert_eq!(
            guardrail.convergence.verified_effective.state,
            StageAnswer::Unknown
        );
        assert_eq!(guardrail.freshness.state, FreshnessState::Stale);
        assert_ne!(
            guardrail.freshness.observed_at.as_deref(),
            Some(bootstrap.generated_at.as_str())
        );

        let discovery = bootstrap
            .capabilities
            .iter()
            .find(|capability| capability.id == "community.agent_discovery")
            .unwrap();
        assert_eq!(discovery.availability, Availability::Stale);
        assert_eq!(discovery.freshness.state, FreshnessState::Stale);
        assert_eq!(bootstrap.community_contract.id, "CJC-090");
        assert!(bootstrap.community_contract.digest.starts_with("sha256:"));
    }

    #[test]
    fn loopback_bind_detection() {
        for lo in [
            "127.0.0.1:8788",
            "127.0.0.1",
            "127.1.2.3:80",
            "localhost:8788",
            "[::1]:8788",
            "::1",
        ] {
            assert!(is_loopback_bind(lo), "{lo} is loopback");
        }
        for pub_ in [
            "0.0.0.0:8788",
            "192.168.0.62:8788",
            "10.0.0.5:80",
            "0.0.0.0",
            "127.attacker.example:8788",
            "localhost.attacker.example:8788",
        ] {
            assert!(!is_loopback_bind(pub_), "{pub_} is NOT loopback");
        }
    }

    #[test]
    fn local_dashboard_rejects_dns_rebinding_host_headers() {
        assert!(host_header_is_allowed(Some("127.0.0.1:8788"), false));
        assert!(host_header_is_allowed(Some("[::1]:8788"), false));
        assert!(host_header_is_allowed(Some("localhost:8788"), false));
        assert!(!host_header_is_allowed(
            Some("127.attacker.example:8788"),
            false
        ));
        assert!(!host_header_is_allowed(
            Some("attacker.example:8788"),
            false
        ));
        assert!(!host_header_is_allowed(None, false));
        assert!(host_header_is_allowed(Some("attacker.example:8788"), true));
    }

    #[test]
    fn has_extension_distinguishes_assets_from_spa_routes() {
        assert!(has_extension("assets/index-abc.js"));
        assert!(has_extension("favicon.ico"));
        assert!(!has_extension("cases")); // SPA client route
        assert!(!has_extension("deep/link"));
    }

    #[test]
    fn dist_is_embedded() {
        // The built React bundle must be embedded, or the dashboard serves nothing.
        assert!(
            innerwarden_dashboard_kit::assets::get("index.html").is_some(),
            "index.html embedded"
        );
    }

    #[test]
    fn agents_payload_is_private_and_read_only() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        std::fs::create_dir_all(home.path().join(".openclaw")).unwrap();
        std::fs::write(
            home.path().join(".openclaw/openclaw.json"),
            "{ gateway: { port: 18789 } }",
        )
        .unwrap();
        let config = r#"{"mcpServers":{"local":{"command":"npx"}}}"#;
        let config_path = home.path().join(".cursor/mcp.json");
        std::fs::write(&config_path, config).unwrap();

        let rows = innerwarden_agent_guard::agents_ops::rows(home.path());
        let body = agents_json(home.path(), &rows);
        let payload: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(payload["schema_version"], AGENTS_SCHEMA_VERSION);
        assert_eq!(payload["discovery_limited"], false);
        assert_eq!(payload["auto_connect"]["status"], "available");
        assert_eq!(payload["auto_connect"]["enabled"], false);
        assert_eq!(payload["auto_connect"]["mode"], "disabled");
        let cursor = payload["agents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|agent| agent["id"] == "cursor")
            .unwrap();
        assert_eq!(cursor["guardrail"]["setup_support"], "automatic");
        assert_eq!(cursor["auto_connect_eligible"], true);
        let openclaw = payload["agents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|agent| agent["id"] == "openclaw")
            .unwrap();
        // OpenClaw became automatically guardable on 2026-08-05, once `mcp_wire`
        // could locate a nested `mcp.servers` table, so the MECHANISM is now
        // automatic.
        assert_eq!(openclaw["guardrail"]["setup_support"], "automatic");
        // Eligibility is a separate question about THIS file, and this fixture
        // is genuinely JSON5 (`{ gateway: ... }`, an unquoted key). The strict
        // reader refuses it, so nothing would be rewritten. That refusal IS the
        // safety property: a file we cannot round-trip losslessly is left alone
        // rather than mangled.
        assert_eq!(
            openclaw["auto_connect_eligible"], false,
            "a JSON5 config must not be reported as ready to rewrite"
        );
        assert!(openclaw["detected_by"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("configuration_file")));
        assert!(!body.contains("\"pids\""));
        assert!(!body.contains("\"config_path\""));
        assert_eq!(std::fs::read_to_string(config_path).unwrap(), config);
        assert!(!crate::agent_policy::config_path(home.path()).exists());
    }

    #[test]
    fn agents_loading_payload_uses_the_same_v2_contract() {
        let payload: serde_json::Value =
            serde_json::from_str(&agents_loading_json(None)).expect("loading payload JSON");
        assert_eq!(payload["schema_version"], AGENTS_SCHEMA_VERSION);
        assert_eq!(payload["availability"], "loading");
        assert_eq!(payload["agents"], serde_json::json!([]));
    }

    #[test]
    fn agents_payload_exposes_precise_non_authorizing_evidence() {
        use innerwarden_agent_guard::agents::{AgentStatus, DiscoveryEvidence};

        let home = tempfile::TempDir::new().unwrap();
        let rows = vec![AgentStatus {
            name: "openclaw".into(),
            pids: Vec::new(),
            installed: false,
            evidence: vec![DiscoveryEvidence::PossibleLeftover],
            hookable: false,
            mcp_json: None,
            mcp_toml: None,
            guarded: false,
        }];

        let payload: serde_json::Value =
            serde_json::from_str(&agents_json(home.path(), &rows)).unwrap();
        let agent = &payload["agents"][0];
        assert_eq!(agent["installed"], false);
        assert_eq!(
            agent["detected_by"],
            serde_json::json!(["possible_leftover"])
        );
        assert_eq!(agent["guardrail"]["setup_support"], "unsupported");
        assert_eq!(agent["auto_connect_eligible"], false);
    }

    #[test]
    fn agents_payload_does_not_claim_a_wrong_matcher_hook_is_guarding_bash() {
        let home = tempfile::TempDir::new().unwrap();
        let settings_path = home.path().join(".claude/settings.json");
        std::fs::create_dir_all(settings_path.parent().unwrap()).unwrap();
        std::fs::write(
            &settings_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "hooks": {"PreToolUse": [{
                    "matcher": "Write",
                    "hooks": [{
                        "type": "command",
                        "command": "\"/opt/innerwarden\" hook --block-review"
                    }]
                }]}
            }))
            .unwrap(),
        )
        .unwrap();

        let rows = innerwarden_agent_guard::agents_ops::rows(home.path());
        let claude = rows
            .iter()
            .find(|agent| agent.name == "claude-code")
            .unwrap();
        assert!(!claude.guarded);
        assert!(innerwarden_agent_guard::agents_ops::status_has_guard_wiring(home.path(), claude));
        assert!(
            !innerwarden_agent_guard::agents_ops::status_is_effectively_guarded(
                home.path(),
                claude
            )
        );

        let payload: serde_json::Value =
            serde_json::from_str(&agents_json(home.path(), &rows)).unwrap();
        let claude = payload["agents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|agent| agent["id"] == "claude-code")
            .unwrap();
        assert_eq!(claude["guardrail"]["mode"], "not_configured");
        let status = guardrail_status_from_rows(home.path(), &rows);
        assert_eq!(status.guarded_agents, 0);
        assert_eq!(status.mode, "not_configured");
    }

    #[test]
    fn agents_payload_does_not_mask_a_corrupt_policy_as_disabled() {
        let home = tempfile::TempDir::new().unwrap();
        let path = crate::agent_policy::config_path(home.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "auto_connect = maybe").unwrap();
        let rows = innerwarden_agent_guard::agents_ops::rows(home.path());
        let payload: serde_json::Value =
            serde_json::from_str(&agents_json(home.path(), &rows)).unwrap();
        assert_eq!(payload["auto_connect"]["status"], "unavailable");
        assert_eq!(payload["auto_connect"]["enabled"], serde_json::Value::Null);
        assert_eq!(payload["auto_connect"]["mode"], serde_json::Value::Null);
        assert_eq!(
            payload["auto_connect"]["watcher"]["lifecycle"],
            "unavailable"
        );
        assert_eq!(
            payload["auto_connect"]["watcher"]["policy_enabled"],
            serde_json::Value::Null
        );
        assert_eq!(
            payload["auto_connect"]["watcher"]["effective_policy_mode"],
            serde_json::Value::Null
        );
    }

    #[test]
    fn agents_payload_projects_live_watcher_policy_separately_from_agent_detection() {
        let home = tempfile::TempDir::new().unwrap();
        let rows = innerwarden_agent_guard::agents_ops::rows(home.path());
        let watcher = std::sync::Arc::new(std::sync::RwLock::new(
            crate::agent_policy::DashboardReconcilerStatus {
                lifecycle: crate::agent_policy::WatcherLifecycle::Running,
                policy_available: true,
                policy_enabled: Some(true),
                effective_policy_mode: Some("monitor".into()),
                last_reconcile_at_ms: Some(123),
                reason_code: None,
            },
        ));
        let payload: serde_json::Value = serde_json::from_str(&agents_json_with_status(
            home.path(),
            &rows,
            false,
            Some(&watcher),
        ))
        .unwrap();

        let status = &payload["auto_connect"]["watcher"];
        assert_eq!(status["lifecycle"], "running");
        assert_eq!(status["policy_available"], true);
        assert_eq!(status["policy_enabled"], true);
        assert_eq!(status["effective_policy_mode"], "monitor");
        assert_eq!(status["last_reconcile_at_ms"], 123);
    }

    #[test]
    fn api_overlay_reads_current_watcher_state_without_waiting_for_agent_rescan() {
        let stale = serde_json::json!({
            "auto_connect": {
                "status": "available",
                "enabled": true,
                "mode": "monitor",
                "watcher": {
                    "lifecycle": "starting",
                    "policy_available": false,
                    "policy_enabled": null,
                    "effective_policy_mode": null,
                    "last_reconcile_at_ms": null,
                    "reason_code": "watcher_starting"
                }
            },
            "agents": []
        })
        .to_string();
        let watcher = std::sync::Arc::new(std::sync::RwLock::new(
            crate::agent_policy::DashboardReconcilerStatus {
                lifecycle: crate::agent_policy::WatcherLifecycle::Running,
                policy_available: true,
                policy_enabled: Some(false),
                effective_policy_mode: Some("disabled".into()),
                last_reconcile_at_ms: Some(456),
                reason_code: None,
            },
        ));

        let payload: serde_json::Value =
            serde_json::from_str(&agent_payload_with_live_watcher(stale, Some(&watcher))).unwrap();
        let status = &payload["auto_connect"]["watcher"];
        assert_eq!(payload["auto_connect"]["status"], "available");
        assert_eq!(payload["auto_connect"]["enabled"], false);
        assert_eq!(payload["auto_connect"]["mode"], "disabled");
        assert_eq!(status["lifecycle"], "running");
        assert_eq!(status["policy_enabled"], false);
        assert_eq!(status["effective_policy_mode"], "disabled");
        assert_eq!(status["last_reconcile_at_ms"], 456);
    }

    #[test]
    fn api_overlay_never_turns_unreadable_live_policy_into_disabled() {
        let stale = serde_json::json!({
            "auto_connect": {
                "status": "available",
                "enabled": false,
                "mode": "disabled",
                "watcher": {}
            },
            "agents": []
        })
        .to_string();
        let watcher = std::sync::Arc::new(std::sync::RwLock::new(
            crate::agent_policy::DashboardReconcilerStatus {
                lifecycle: crate::agent_policy::WatcherLifecycle::Running,
                policy_available: false,
                policy_enabled: None,
                effective_policy_mode: None,
                last_reconcile_at_ms: Some(789),
                reason_code: Some("policy_unavailable".into()),
            },
        ));

        let payload: serde_json::Value =
            serde_json::from_str(&agent_payload_with_live_watcher(stale, Some(&watcher))).unwrap();
        assert_eq!(payload["auto_connect"]["status"], "unavailable");
        assert_eq!(payload["auto_connect"]["enabled"], serde_json::Value::Null);
        assert_eq!(payload["auto_connect"]["mode"], serde_json::Value::Null);
    }

    #[test]
    fn api_overlay_projects_cli_off_without_waiting_for_agent_rescan() {
        let home = tempfile::TempDir::new().unwrap();
        crate::agent_policy::set_auto_connect(
            home.path(),
            true,
            crate::agent_policy::DesiredMode::Monitor,
        )
        .unwrap();
        let watcher = crate::agent_policy::spawn_dashboard_reconciler_with_interval(
            home.path().to_path_buf(),
            "/abs/innerwarden".into(),
            std::time::Duration::from_millis(10),
        )
        .unwrap();
        let shared = watcher.status();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while crate::agent_policy::read_dashboard_reconciler_status(&shared).policy_enabled
            != Some(true)
        {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let rows = innerwarden_agent_guard::agents_ops::rows(home.path());
        let stale = agents_json_with_status(home.path(), &rows, false, Some(&shared));

        crate::agent_policy::disable_auto_connect(home.path()).unwrap();
        while crate::agent_policy::read_dashboard_reconciler_status(&shared).policy_enabled
            != Some(false)
        {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let payload: serde_json::Value =
            serde_json::from_str(&agent_payload_with_live_watcher(stale, Some(&shared))).unwrap();
        assert_eq!(payload["auto_connect"]["status"], "available");
        assert_eq!(payload["auto_connect"]["enabled"], false);
        assert_eq!(payload["auto_connect"]["mode"], "disabled");
    }

    #[test]
    fn aggregate_status_surfaces_partial_wiring_instead_of_hiding_it() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        std::fs::write(
            home.path().join(".cursor/mcp.json"),
            r#"{"mcpServers":{"guarded":{"command":"innerwarden","args":["proxy","--mode","advisory","--","npx","one"]},"late":{"command":"npx","args":["two"]}}}"#,
        )
        .unwrap();
        let rows = innerwarden_agent_guard::agents_ops::rows(home.path());

        let status = guardrail_status_from_rows(home.path(), &rows);

        assert_eq!(status.mode, "partial");
        assert_eq!(status.guarded_agents, 1);
    }
}
