//! Thin I/O for `innerwarden openclaw`: OpenClaw's own tools, screened.
//!
//! The decisions live in the pure `openclaw_guard` module. This file reads
//! the call the plugin hands over, runs it through the hook's own screening
//! (`screen_shell`, `screen_file_writes` in `main.rs`), asks InnerWarden Pro
//! on this host's loopback where Pro is installed, writes the record, and
//! lays the plugin's files and its entry in `openclaw.json`.
//!
//! `screen` always answers with one JSON line on stdout and exits 0; the
//! plugin reads no answer as a refusal in enforce. Everything else exits 0
//! on anything short of operator error: it runs inside a chat gateway.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};

use crate::observe::{InstalledFiles, ShippedFile};
use crate::observe_io::Refreshed;
use crate::openclaw_guard::{
    self as guard, Decision, Mode, ProStatus, Resolution, Screen, SuggestionFacts, ToolCall,
    Trigger, AGENT, PLUGIN_ID, SCREENED_TOOLS,
};

const ENTRY: &str = include_str!("../assets/openclaw-guard/index.js");
const MANIFEST: &str = include_str!("../assets/openclaw-guard/openclaw.plugin.json");
const PACKAGE: &str = include_str!("../assets/openclaw-guard/package.json");

/// The plugin's files, its entry first. No earlier release shipped it.
pub(crate) const FILES: [ShippedFile; 3] = [
    ShippedFile {
        name: "index.js",
        body: ENTRY,
        earlier: &[],
    },
    ShippedFile {
        name: "openclaw.plugin.json",
        body: MANIFEST,
        earlier: &[],
    },
    ShippedFile {
        name: "package.json",
        body: PACKAGE,
        earlier: &[],
    },
];

/// The most stdin one call reads.
const MAX_STDIN_BYTES: u64 = 1024 * 1024;

/// One check-command request to Pro on this host's loopback, connect to
/// answer. The screening runs on every tool call, so a Pro that is down or
/// busy costs at most this, and the local verdict stands. Pro's own Claude
/// Code hook waits up to 8 s; a loaded lab host (test001, 2026-10-24)
/// answered in 4.5 s, so this is a bound on a slow answer, not a forecast.
const PRO_TIMEOUT: Duration = Duration::from_secs(3);

/// One status request. Asked for an approval card, `agents list` and the
/// dashboard, never for every call, and Pro reads the kernel's maps, the
/// licence and the caller's cgroup to answer it.
const PRO_STATUS_TIMEOUT: Duration = Duration::from_secs(3);

/// Pro's routes this asks.
const CHECK_COMMAND_PATH: &str = "/api/agent/check-command";
const STATUS_PATH: &str = "/api/agent/protection-status";

/// The suggestion's state, beside the record.
const SUGGESTION_FILE: &str = "pro-suggestion.json";

/// The seconds of slack around a call a kernel refusal is matched within.
const KERNEL_SLACK_SECONDS: u64 = 2;

/// The `--agent` the screening reads, as the hook reads its own line.
fn agent_args() -> Vec<String> {
    vec!["--agent".to_string(), AGENT.to_string()]
}

pub fn cmd(rest: &[String]) -> std::process::ExitCode {
    match rest.first().map(String::as_str) {
        Some("screen") => cmd_screen(&rest[1..]),
        Some("resolved") => cmd_resolved(&rest[1..]),
        Some("ran") => cmd_ran(),
        None | Some("status") => cmd_status(),
        Some("help") => {
            println!("{}", help_text());
            std::process::ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("innerwarden openclaw: unknown subcommand `{other}`\n");
            println!("{}", help_text());
            std::process::ExitCode::from(2)
        }
    }
}

pub(crate) fn help_text() -> String {
    let prog = crate::prog();
    format!(
        "{prog} openclaw - OpenClaw's own tools, screened before they run.\n\
         \n\
         OpenClaw runs commands and changes files through its own tools (exec,\n\
         process, write, edit, apply_patch). The plugin `{PLUGIN_ID}`, which\n\
         `{prog} agents connect openclaw` installs next to the MCP proxy, asks\n\
         this binary about each call before it runs.\n\
         \n\
         Monitor (the default) records only. `{prog} enforce` turns refusals on:\n\
         a deny is refused (the model hears only \"{reason}\"), a\n\
         review asks you to allow it once or deny it.\n\
         \n\
         Usage:\n  \
         {prog} openclaw [status]      is the plugin installed, in which mode, and\n  \
         \x20                             what InnerWarden Pro says about this host\n\
         \n\
         The plugin itself runs `{prog} openclaw screen|resolved|ran`; they read\n\
         one call as JSON on stdin and are not meant to be typed.",
        reason = guard::MODEL_REASON,
    )
}

fn read_stdin() -> String {
    let mut buffer = String::new();
    let _ = std::io::stdin()
        .take(MAX_STDIN_BYTES)
        .read_to_string(&mut buffer);
    buffer
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn flag(rest: &[String], name: &str) -> Option<String> {
    let at = rest.iter().position(|a| a == name)?;
    rest.get(at + 1).cloned()
}

fn answer_line(value: &Value) -> std::process::ExitCode {
    println!("{value}");
    std::process::ExitCode::SUCCESS
}

// ── screen ───────────────────────────────────────────────────────────────────

/// `innerwarden openclaw screen --mode monitor|enforce`: judge one call.
///
/// A review in enforce is not recorded here: its outcome is the person's,
/// and `resolved` records it once they answered. Everything else is
/// recorded now, as the Claude Code hook records it.
fn cmd_screen(rest: &[String]) -> std::process::ExitCode {
    let mode = Mode::parse(flag(rest, "--mode").as_deref());
    let monitor = mode == Mode::Monitor;
    let Ok(call) = serde_json::from_str::<ToolCall>(&read_stdin()) else {
        // Unreadable: the plugin refuses in enforce, records nothing in monitor.
        return answer_line(&json!({ "decision": "deny", "unreadable": true }));
    };
    if !SCREENED_TOOLS.contains(&call.tool.as_str()) {
        return answer_line(&guard::answer(Decision::Allow, None, None));
    }
    let screen = guard::what_to_screen(&call);
    let buf = guard::hook_payload(&call, &screen);
    let rest = agent_args();
    match &screen {
        Screen::Nothing => answer_line(&guard::answer(Decision::Allow, None, None)),
        Screen::Unreadable(_) => answer_line(&json!({
            "decision": (if monitor { "allow" } else { "deny" }),
            "unreadable": true,
        })),
        Screen::Files { tool, paths } => {
            match crate::screen_file_writes(&buf, &rest, monitor, tool, paths) {
                crate::FileScreen::Pass => answer_line(&guard::answer(Decision::Allow, None, None)),
                crate::FileScreen::Refused { .. } => {
                    answer_line(&guard::answer(Decision::Deny, None, None))
                }
            }
        }
        Screen::Shell { .. } => screen_command(&call, &screen, &buf, &rest, mode),
    }
}

fn screen_command(
    call: &ToolCall,
    screen: &Screen,
    buf: &str,
    rest: &[String],
    mode: Mode,
) -> std::process::ExitCode {
    let monitor = mode == Mode::Monitor;
    let pro_installed = crate::upsell_io::active_defence_installed();
    let ask_pro = |command: &str| pro_check_command(command);
    let options = crate::ShellScreenOptions {
        monitor,
        block_review: true,
        record: false,
        host: pro_installed.then_some(&ask_pro as crate::HostAsk<'_>),
    };
    let screened = match crate::screen_shell(buf, rest, &options) {
        crate::ShellScreen::Nothing => {
            return answer_line(&guard::answer(Decision::Allow, None, None))
        }
        crate::ShellScreen::Unreadable(_) | crate::ShellScreen::ProfilesInvalid(_) => {
            return answer_line(&json!({
                "decision": (if monitor { "allow" } else { "deny" }),
                "unreadable": true,
            }))
        }
        crate::ShellScreen::Screened(screened) => screened,
    };
    let recommendation = screened
        .verdict
        .get("recommendation")
        .and_then(Value::as_str)
        .unwrap_or("deny");
    let decision = Decision::from_recommendation(recommendation);
    // What InnerWarden Pro answered, when it was asked: for the record and
    // the plugin's log, never for the model.
    let host = screened.verdict.get("host_recommendation").cloned();
    let with_host = |mut answer: Value| {
        if let Some(host) = &host {
            answer["host"] = host.clone();
        }
        answer
    };
    if monitor || decision != Decision::Review {
        crate::record_shell(
            buf,
            rest,
            &screened.command,
            &screened.verdict,
            monitor,
            decision != Decision::Allow,
            screened.layer.clone(),
        );
        return answer_line(&with_host(guard::answer(decision, None, None)));
    }
    // Enforce, review: the person is asked; recorded once they answer.
    let pro = pro_installed.then(pro_status).flatten();
    let owner_surface = call.owner == Some(true) && call.channel == "webchat";
    let line = take_suggestion(
        Some(Trigger::ProgramExecution),
        owner_surface,
        pro_installed,
        pro.clone(),
    );
    let risk = screened
        .verdict
        .get("risk_score")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let card = guard::card(screen, risk, pro.as_ref(), line.as_deref());
    let record = json!({
        "command": screened.command,
        "verdict": screened.verdict,
    });
    answer_line(&with_host(guard::answer(
        Decision::Review,
        Some(&card),
        Some(record),
    )))
}

// ── resolved ─────────────────────────────────────────────────────────────────

/// `innerwarden openclaw resolved --decision <d>`: record a review once the
/// person answered (or nobody did, which is a refusal).
fn cmd_resolved(rest: &[String]) -> std::process::ExitCode {
    let resolution = Resolution::parse(flag(rest, "--decision").as_deref().unwrap_or(""));
    let Ok(body) = serde_json::from_str::<Value>(&read_stdin()) else {
        return std::process::ExitCode::SUCCESS;
    };
    let Ok(call) =
        serde_json::from_value::<ToolCall>(body.get("call").cloned().unwrap_or_default())
    else {
        return std::process::ExitCode::SUCCESS;
    };
    let Some(record) = body.get("record").filter(|r| r.is_object()) else {
        return std::process::ExitCode::SUCCESS;
    };
    let Some(command) = record.get("command").and_then(Value::as_str) else {
        return std::process::ExitCode::SUCCESS;
    };
    let verdict = record.get("verdict").cloned().unwrap_or_else(|| json!({}));
    let verdict = guard::resolved_verdict(verdict, resolution);
    let buf = guard::hook_payload(
        &call,
        &Screen::Shell {
            command: command.to_string(),
        },
    );
    crate::record_shell(
        &buf,
        &agent_args(),
        command,
        &verdict,
        false,
        !resolution.ran(),
        None,
    );
    std::process::ExitCode::SUCCESS
}

// ── ran ──────────────────────────────────────────────────────────────────────

/// `innerwarden openclaw ran`: a call that ended in a way worth a look. A
/// program call whose result reads like a refusal of the kernel: where Pro
/// is installed, the refusals its gate made in this agent's scope during
/// the call are recorded against the chat the call belonged to, each as Pro
/// recorded it. A call that ran other than as it was screened (a plugin
/// froze a rewrite of its own under an approval) is recorded as such.
fn cmd_ran() -> std::process::ExitCode {
    let Ok(body) = serde_json::from_str::<Value>(&read_stdin()) else {
        return std::process::ExitCode::SUCCESS;
    };
    let Some(dir) = record_dir() else {
        return std::process::ExitCode::SUCCESS;
    };
    let session = body
        .get("session")
        .and_then(Value::as_str)
        .map(crate::graph_io::bounded_session)
        .unwrap_or_default();
    let tool_call = body
        .get("tool_call_id")
        .and_then(Value::as_str)
        .map(|id| id.chars().take(96).collect::<String>())
        .unwrap_or_default();
    if body.get("rewritten").and_then(Value::as_bool) == Some(true) {
        crate::graph_io::append_guard_event_at(
            &dir,
            &json!({
                "kind": "guard.call_rewritten",
                "ts": now(),
                "agent": AGENT,
                "session": session,
                "tool": body.get("tool").and_then(Value::as_str).unwrap_or(""),
                "tool_call": tool_call,
                "detail": "the call ran other than as InnerWarden screened it: another OpenClaw plugin changed its parameters",
            }),
        );
        crate::notify_io::fire_text(
            "InnerWarden: an OpenClaw tool call ran other than as it was screened (another plugin changed it).",
        );
    }
    if !crate::upsell_io::active_defence_installed() {
        return std::process::ExitCode::SUCCESS;
    }
    let ms = |key: &str| body.get(key).and_then(Value::as_u64).map(|ms| ms / 1000);
    let (Some(started), Some(ended)) = (ms("started_ms"), ms("ended_ms")) else {
        return std::process::ExitCode::SUCCESS;
    };
    let from = started.saturating_sub(KERNEL_SLACK_SECONDS);
    let until = ended.saturating_add(KERNEL_SLACK_SECONDS);
    for refusal in pro_refusals(from).unwrap_or_default() {
        if refusal.ts < from || refusal.ts > until {
            continue;
        }
        crate::graph_io::append_guard_event_at(
            &dir,
            &json!({
                "kind": "guard.kernel_refused",
                "ts": now(),
                "refused_at": refusal.ts,
                "agent": AGENT,
                "session": session,
                "tool_call": tool_call,
                "program": refusal.program,
            }),
        );
    }
    std::process::ExitCode::SUCCESS
}

/// The directory the record and the sink live in.
fn record_dir() -> Option<PathBuf> {
    crate::graph_io::graph_path().and_then(|path| path.parent().map(Path::to_path_buf))
}

// ── Pro on this host ─────────────────────────────────────────────────────────

/// An HTTP client for this host's loopback only: Pro answers there with a
/// certificate of its own, so verification is relaxed for loopback and for
/// nothing else (`agent_report::agent_route` refuses any other host).
fn loopback_agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .http_status_as_error(false)
        .tls_config(
            ureq::tls::TlsConfig::builder()
                .disable_verification(true)
                .build(),
        )
        .build()
        .into()
}

fn pro_url(path: &str) -> Option<String> {
    crate::agent_report::agent_route(
        std::env::var(crate::agent_report::AGENT_URL_VAR)
            .ok()
            .as_deref(),
        path,
    )
}

/// Pro's own recommendation for `command`, from its `check-command`
/// (`{command, agent_name, runs_only_on_allow}`, the contract the Claude
/// Code hook of Pro uses). `None` when Pro did not answer.
pub(crate) fn pro_check_command(command: &str) -> Option<String> {
    let url = pro_url(CHECK_COMMAND_PATH)?;
    let mut response = loopback_agent(PRO_TIMEOUT)
        .post(&url)
        .send_json(json!({
            "command": command,
            "agent_name": AGENT,
            "runs_only_on_allow": true,
        }))
        .ok()?;
    if response.status().as_u16() != 200 {
        return None;
    }
    let body: Value = response.body_mut().read_json().ok()?;
    body.get("recommendation")
        .and_then(Value::as_str)
        .filter(|rec| matches!(*rec, "allow" | "review" | "deny"))
        .map(str::to_string)
}

fn pro_status_answer(since: Option<u64>) -> Option<Value> {
    let mut url = pro_url(STATUS_PATH)?;
    if let Some(since) = since {
        url.push_str(&format!("?since={since}"));
    }
    let mut response = loopback_agent(PRO_STATUS_TIMEOUT).get(&url).call().ok()?;
    if response.status().as_u16() != 200 {
        return None;
    }
    response.body_mut().read_json().ok()
}

/// What Pro says about this host, for the person. `None` when it did not
/// answer.
pub(crate) fn pro_status() -> Option<ProStatus> {
    pro_status_answer(None).and_then(|answer| ProStatus::from_answer(&answer))
}

/// One refusal Pro's Execution Gate made in this caller's scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KernelRefusal {
    pub ts: u64,
    pub program: String,
}

/// The refusals Pro's gate made, in enforce, in this caller's scope, since
/// `since`: Pro's own record, read from root's store and checked against
/// the live gate. `None` when Pro did not answer.
pub(crate) fn pro_refusals(since: u64) -> Option<Vec<KernelRefusal>> {
    let answer = pro_status_answer(Some(since))?;
    let list = answer.pointer("/exec_gate/refusals")?.as_array()?;
    Some(
        list.iter()
            .filter_map(|refusal| {
                Some(KernelRefusal {
                    ts: refusal.get("ts")?.as_u64()?,
                    program: refusal
                        .get("program")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .chars()
                        .take(256)
                        .collect(),
                })
            })
            .collect(),
    )
}

// ── the suggestion ───────────────────────────────────────────────────────────

/// The suggestion's state: when it was last shown, and whether the person
/// said "Not now".
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct SuggestionState {
    #[serde(default)]
    shown_at: Option<u64>,
    /// Reserved for a "Not now" the person gives outside a browser; the
    /// dashboard's own "Not now" is kept in its browser (`dismiss.ts`).
    #[serde(default)]
    not_now_at: Option<u64>,
}

fn suggestion_path() -> Option<PathBuf> {
    record_dir().map(|dir| dir.join(SUGGESTION_FILE))
}

fn suggestion_state() -> SuggestionState {
    suggestion_path()
        .and_then(|path| innerwarden_safe_io::open_no_follow(&path).ok())
        .and_then(|mut file| {
            let mut text = String::new();
            (&mut file).take(4096).read_to_string(&mut text).ok()?;
            serde_json::from_str(&text).ok()
        })
        .unwrap_or_default()
}

fn save_suggestion_state(state: &SuggestionState) {
    let Some(path) = suggestion_path() else {
        return;
    };
    if std::fs::symlink_metadata(&path).is_ok_and(|meta| meta.file_type().is_symlink()) {
        return;
    }
    if let Ok(text) = serde_json::to_string(state) {
        let _ = std::fs::write(path, text + "\n");
    }
}

/// The suggestion for this trigger, and its showing remembered when it is
/// shown unasked.
pub(crate) fn take_suggestion(
    trigger: Option<Trigger>,
    owner_surface: bool,
    pro_installed: bool,
    pro: Option<ProStatus>,
) -> Option<String> {
    let mut state = suggestion_state();
    let facts = SuggestionFacts {
        linux: cfg!(target_os = "linux"),
        pro_installed,
        pro,
        trigger,
        owner_surface,
        now: now(),
        last_shown: state.shown_at,
        not_now: state.not_now_at.is_some(),
    };
    let line = guard::suggestion(&facts)?;
    if trigger != Some(Trigger::OwnerAsked) {
        state.shown_at = Some(facts.now);
        save_suggestion_state(&state);
    }
    Some(line)
}

/// How far back the record is read for what a suggestion on the dashboard
/// rests on: the week it stays quiet for.
const TRIGGER_LOOKBACK_SECONDS: u64 = guard::SUGGESTION_QUIET_SECONDS;

/// The tail of the sink read for a trigger, bounded like `observe`'s.
const SINK_TAIL_BYTES: u64 = 256 * 1024;

fn sink_tail() -> String {
    let Some(dir) = record_dir() else {
        return String::new();
    };
    let Ok(mut file) = innerwarden_safe_io::open_no_follow(&dir.join("guard-events.jsonl")) else {
        return String::new();
    };
    let Ok(metadata) = file.metadata() else {
        return String::new();
    };
    if !innerwarden_safe_io::is_regular_file(&metadata) {
        return String::new();
    }
    if metadata.len() > SINK_TAIL_BYTES {
        use std::io::Seek;
        let _ = file.seek(std::io::SeekFrom::Start(metadata.len() - SINK_TAIL_BYTES));
    }
    let mut buffer = String::new();
    let _ = file.take(SINK_TAIL_BYTES).read_to_string(&mut buffer);
    buffer
}

/// What the dashboard's Agents page says about OpenClaw's own tools, on the
/// OpenClaw card: the guard's state, Pro's status and the suggestion, on the
/// measured fact the record holds. Read by the person on this machine only.
/// Pro's status is asked at most every [`DASHBOARD_TTL`].
pub(crate) fn dashboard_field(home: &Path) -> Value {
    use std::sync::Mutex;
    use std::time::Instant;
    static CACHE: Mutex<Option<(Instant, Value)>> = Mutex::new(None);
    if let Ok(cache) = CACHE.lock() {
        if let Some((at, value)) = cache.as_ref() {
            if at.elapsed() < DASHBOARD_TTL {
                return value.clone();
            }
        }
    }
    let state = state(home);
    let pro_installed = crate::upsell_io::active_defence_installed();
    let pro = pro_installed.then(pro_status).flatten();
    let trigger =
        guard::trigger_from_sink(&sink_tail(), now().saturating_sub(TRIGGER_LOOKBACK_SECONDS));
    let suggestion = take_suggestion(trigger, true, pro_installed, pro.clone());
    let value = json!({
        "screened": state.files && state.mode.is_some() && !state.turned_off,
        "mode": state.mode.map(Mode::as_str),
        "turned_off": state.turned_off,
        "pro_installed": pro_installed,
        "pro_line": pro.as_ref().map(ProStatus::line),
        "suggestion": suggestion,
    });
    if let Ok(mut cache) = CACHE.lock() {
        *cache = Some((Instant::now(), value.clone()));
    }
    value
}

/// The agents' payload with OpenClaw's own tools on the OpenClaw card
/// (`own_tools`, [`dashboard_field`]), where this account has an OpenClaw
/// config. Anything unreadable is left as it was.
pub(crate) fn with_own_tools(body: String) -> String {
    let Ok(home) = innerwarden_agent_guard::hook::home_dir() else {
        return body;
    };
    if !crate::observe_io::openclaw_config(&home).is_file() {
        return body;
    }
    let Ok(mut value) = serde_json::from_str::<Value>(&body) else {
        return body;
    };
    let Some(agents) = value.get_mut("agents").and_then(Value::as_array_mut) else {
        return body;
    };
    let Some(openclaw) = agents
        .iter_mut()
        .find(|agent| agent.get("id").and_then(Value::as_str) == Some(AGENT))
    else {
        return body;
    };
    openclaw["own_tools"] = dashboard_field(&home);
    value.to_string()
}

/// How long the dashboard keeps one reading of Pro's status.
const DASHBOARD_TTL: Duration = Duration::from_secs(30);

// ── install, mode, removal ───────────────────────────────────────────────────

fn plugin_dir(home: &Path) -> PathBuf {
    home.join(".openclaw/extensions").join(PLUGIN_ID)
}

/// What `agents connect openclaw` did with the guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Installed {
    /// Files written and the entry enabled, in this mode.
    Enabled { mode: Mode, blocker: Option<String> },
    /// The person turned the entry off: files written, entry left off.
    LeftOff,
    /// Nothing was changed, for this reason.
    Failed(String),
}

fn read_root(config_path: &Path) -> Result<(Vec<u8>, Value), String> {
    let source = innerwarden_agent_guard::file_update::read_config(config_path)?
        .ok_or_else(|| format!("{} disappeared while reading it", config_path.display()))?;
    let root = serde_json::from_slice::<Value>(&source).map_err(|_| {
        format!(
            "{} is not strict JSON, so it was left untouched; enable the guard by hand: \
             plugins.entries.{PLUGIN_ID}.enabled = true",
            config_path.display()
        )
    })?;
    Ok((source, root))
}

fn write_root(config_path: &Path, source: &[u8], root: &Value) -> Result<(), String> {
    let body = serde_json::to_string_pretty(root).map_err(|e| e.to_string())? + "\n";
    innerwarden_agent_guard::file_update::replace_if_unchanged(
        config_path,
        Some(source),
        body.as_bytes(),
    )
}

/// Lay the plugin's files and enable its entry, in monitor unless it holds a
/// mode already. `binary`: the absolute path the plugin runs.
pub(crate) fn install(home: &Path, binary: &str) -> Installed {
    let config_path = crate::observe_io::openclaw_config(home);
    if !config_path.is_file() {
        return Installed::Failed(format!("no OpenClaw config at {}", config_path.display()));
    }
    let bin_json = json!({ "bin": binary }).to_string() + "\n";
    if let Err(error) = crate::observe_io::write_files(&plugin_dir(home), &FILES, &bin_json) {
        return Installed::Failed(error);
    }
    let (source, root) = match read_root(&config_path) {
        Ok(read) => read,
        Err(error) => return Installed::Failed(error),
    };
    let (updated, entry) = guard::enable_guard_entry(root);
    match entry {
        guard::GuardEntry::LeftOff => Installed::LeftOff,
        guard::GuardEntry::UnexpectedShape => Installed::Failed(format!(
            "plugins.entries.{PLUGIN_ID} in {} is not a table, so it was left as it is",
            config_path.display()
        )),
        guard::GuardEntry::Enabled { changed, mode } => {
            if changed {
                if let Err(error) = write_root(&config_path, &source, &updated) {
                    return Installed::Failed(error);
                }
            }
            let blocker = crate::observe::plugin_blocker(&updated, PLUGIN_ID)
                .filter(|b| *b != crate::observe::PluginBlocker::NoConversationAccess)
                .map(|b| b.key(PLUGIN_ID));
            Installed::Enabled { mode, blocker }
        }
    }
}

/// The lines `agents connect openclaw` prints about the guard.
pub(crate) fn install_lines(installed: &Installed, home: &Path) -> Vec<String> {
    let prog = crate::prog();
    let dir = plugin_dir(home);
    match installed {
        Installed::Enabled { mode, blocker } => {
            let mut lines = vec![format!(
                "  openclaw - its own tools (exec, process, write, edit, apply_patch) are screened by the plugin {PLUGIN_ID} ({}), mode {}",
                dir.display(),
                mode.as_str()
            )];
            if *mode == Mode::Monitor {
                lines.push(format!(
                    "    monitor records what enforce would refuse and refuses nothing; `{prog} enforce` turns refusals on"
                ));
            }
            if let Some(blocker) = blocker {
                lines.push(format!(
                    "    it will not run: {blocker}. That is your plugin policy, and it was left as it is"
                ));
            }
            lines
        }
        Installed::LeftOff => vec![format!(
            "  openclaw - the plugin {PLUGIN_ID} is turned off in your config (plugins.entries.{PLUGIN_ID}), and a connect does not turn back on what you turned off"
        )],
        Installed::Failed(why) => vec![format!(
            "  openclaw - failed: its own tools are NOT screened, the plugin {PLUGIN_ID} could not be installed ({why})"
        )],
    }
}

/// Put the guard in `mode` where it is installed (`enforce`, `dry-run`).
/// `Ok(false)`: not installed, nothing changed.
pub(crate) fn set_mode(home: &Path, mode: Mode) -> Result<bool, String> {
    let config_path = crate::observe_io::openclaw_config(home);
    if !config_path.is_file() {
        return Ok(false);
    }
    let (source, root) = read_root(&config_path)?;
    let (updated, changed) = guard::set_guard_mode(root, mode);
    if changed {
        write_root(&config_path, &source, &updated)?;
    }
    Ok(guard::guard_mode(&updated).is_some())
}

/// Take the guard out (`agents disconnect openclaw`): its entry, and its
/// files where they are exactly what a release wrote. A file somebody
/// changed is left and named.
pub(crate) fn uninstall(home: &Path) -> Vec<String> {
    let mut lines = Vec::new();
    let config_path = crate::observe_io::openclaw_config(home);
    if config_path.is_file() {
        match read_root(&config_path) {
            Ok((source, root)) => {
                let (updated, removed) = guard::remove_guard_entry(root);
                if removed {
                    match write_root(&config_path, &source, &updated) {
                        Ok(()) => lines.push(format!(
                            "  openclaw - the plugin {PLUGIN_ID} was taken out of {}",
                            config_path.display()
                        )),
                        Err(error) => lines.push(format!(
                            "  openclaw - failed: the plugin {PLUGIN_ID} stays in the config ({error})"
                        )),
                    }
                }
            }
            Err(error) => lines.push(format!("  openclaw - failed: {error}")),
        }
    }
    let dir = plugin_dir(home);
    match crate::observe_io::judge(&dir, &FILES) {
        InstalledFiles::NotInstalled => {}
        InstalledFiles::Changed(file) => lines.push(format!(
            "  openclaw - {} was left: {file} is not a file InnerWarden wrote",
            dir.display()
        )),
        InstalledFiles::Current | InstalledFiles::Outdated => {
            for name in FILES.iter().map(|f| f.name).chain(["bin.json"]) {
                let _ = std::fs::remove_file(dir.join(name));
            }
            let _ = std::fs::remove_dir(&dir);
        }
    }
    lines
}

/// Bring the plugin's files up to this version's (`observe refresh`, which
/// `upgrade` runs), where every one is exactly what a release wrote.
pub(crate) fn refresh(home: &Path) -> Refreshed {
    crate::observe_io::refresh_files(home, &plugin_dir(home), &FILES)
}

/// The guard on this host, as `openclaw status` and `agents list` say it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GuardState {
    /// The plugin's files are there.
    pub files: bool,
    /// Its entry's mode, `None` with no entry.
    pub mode: Option<Mode>,
    pub turned_off: bool,
}

pub(crate) fn state(home: &Path) -> GuardState {
    let files = plugin_dir(home).join("index.js").is_file();
    let root = std::fs::read(crate::observe_io::openclaw_config(home))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .unwrap_or_default();
    GuardState {
        files,
        mode: guard::guard_mode(&root),
        turned_off: guard::guard_turned_off(&root),
    }
}

/// The lines about OpenClaw's own tools: the guard's state, what Pro says
/// about this host, and the suggestion, which the person asked for here.
pub(crate) fn status_lines(home: &Path) -> Vec<String> {
    let prog = crate::prog();
    let state = state(home);
    let mut lines = Vec::new();
    let screened = match (state.files, state.mode, state.turned_off) {
        (_, _, true) => format!("turned off in your config (plugins.entries.{PLUGIN_ID})"),
        (true, Some(mode), false) => format!("screened, {}", mode.as_str()),
        _ => format!("not screened (`{prog} agents connect openclaw` installs the guard)"),
    };
    lines.push(format!("  OpenClaw's own tools: {screened}"));
    let pro_installed = crate::upsell_io::active_defence_installed();
    let pro = pro_installed.then(pro_status).flatten();
    if let Some(pro) = &pro {
        lines.push(format!("  {}", pro.line()));
    } else if pro_installed {
        lines.push(
            "  InnerWarden Pro is installed here; its status could not be read on this host's \
             loopback (it is not running, or its release does not serve it yet)."
                .into(),
        );
    }
    if let Some(line) = take_suggestion(Some(Trigger::OwnerAsked), true, pro_installed, pro) {
        lines.push(format!("  {line}"));
    }
    lines
}

/// `innerwarden openclaw status`.
fn cmd_status() -> std::process::ExitCode {
    let home = match innerwarden_agent_guard::hook::home_dir() {
        Ok(home) => home,
        Err(error) => {
            eprintln!("innerwarden openclaw: {error}");
            return std::process::ExitCode::from(2);
        }
    };
    if !crate::observe_io::openclaw_config(&home).is_file() {
        println!("innerwarden openclaw - no OpenClaw config on this account (~/.openclaw/openclaw.json).");
        return std::process::ExitCode::SUCCESS;
    }
    for line in status_lines(&home) {
        println!("{line}");
    }
    std::process::ExitCode::SUCCESS
}
