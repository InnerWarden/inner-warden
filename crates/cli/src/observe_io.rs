//! Thin I/O for `innerwarden observe`: the conversation-attempt surface.
//!
//! The decisions all live in the pure, tested `observe` module. This file reads
//! the message on stdin, resolves the paths, keeps the small pending file
//! between the two hook calls, appends the record to the guard event sink, and
//! installs the OpenClaw hook that drives it. Excluded from the coverage floor
//! like the other adapters.
//!
//! Every command here exits 0 on anything short of operator error. It runs
//! inside a chat gateway, and a telemetry surface that can fail a turn is worse
//! than no telemetry surface.

use innerwarden_agent_guard::mcp::analyze_command;
use innerwarden_agent_guard::rules::{AtrSource, RuleEngine};
use serde_json::Value;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::observe::{
    agent_field, asks_for_a_miner, attempt_line, bounded_field, correlation_window, guard_window,
    needs_block_correlation, outcome, redact_and_bound, AskFindings, Decider, Departure,
    GuardWindow, Leaving, NoReply, Pending, PendingAsk, MAX_ASK_CHARS, PENDING_TTL_SECONDS,
    UNREPORTED_REPLY_WAIT_SECONDS,
};

/// The hook directory name inside `~/.openclaw/hooks/`, and the config key that
/// enables it. OpenClaw derives the config key from the hook name.
const HOOK_NAME: &str = "innerwarden-attempts";

/// The most stdin this reads. A pasted document is not a better attempt record
/// than its first pages, and an unbounded read is a way to stall a gateway.
const MAX_STDIN_BYTES: u64 = 64 * 1024;

/// How much of the sink's tail is searched for a guard block. Comfortably more
/// than a conversation turn produces, and bounded so the check stays cheap on a
/// long-lived sink.
const SINK_TAIL_BYTES: u64 = 256 * 1024;

/// The pending state, beside the graph and the sink.
const PENDING_FILE: &str = "observe-pending.json";

/// How many times one hook call re-reads and re-applies its change when another
/// call changed the pending state first. Hook calls overlap on a busy gateway
/// (every message event is dispatched without waiting for the last), and a
/// lost compare-and-swap used to be skipped, which lost the ask it carried.
const PENDING_UPDATE_ATTEMPTS: usize = 4;

const HOOK_DOC: &str = include_str!("../assets/openclaw-hook/HOOK.md");
const HOOK_HANDLER: &str = include_str!("../assets/openclaw-hook/handler.js");

pub fn cmd(rest: &[String]) -> std::process::ExitCode {
    match rest.first().map(String::as_str) {
        Some("inbound") => cmd_inbound(&rest[1..]),
        Some("reply") => cmd_reply(&rest[1..]),
        Some("settle") => cmd_settle(&rest[1..]),
        Some("install") => cmd_install(&rest[1..]),
        None | Some("status") => cmd_status(),
        // `--help` and `-h` are answered before dispatch (`help::for_invocation`);
        // the bare word still lands here.
        Some("help") => {
            println!("{}", help_text());
            std::process::ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("innerwarden observe: unknown subcommand `{other}`\n");
            println!("{}", help_text());
            std::process::ExitCode::from(2)
        }
    }
}

pub(crate) fn help_text() -> String {
    let prog = crate::prog();
    format!(
        "{prog} observe - record dangerous asks that reach an agent in CONVERSATION.\n\
         \n\
         The guard screens what an agent tries to RUN. An attacker who asks an agent\n\
         to mine crypto and is refused by the model produces no tool call, so nothing\n\
         reaches the guard. This surface records that attempt, and is honest about\n\
         what it proves: the model declined. It is not enforcement.\n\
         \n\
         USAGE:\n  \
           {prog} observe status                    is the surface wired on this host?\n  \
           {prog} observe install [--home <dir>]    wire it into OpenClaw (message hooks)\n  \
           {prog} observe inbound --session <k> [--channel <c>] [--sender <s>] [--agent <a>]\n  \
           \x20                                       score the user text on stdin\n  \
           {prog} observe reply --session <k> [--channel <c>] [--decider <d>]\n  \
           \x20                                       close the attempt the session was waiting on\n  \
           {prog} observe settle --session <k>\n  \
           \x20                                       close it where the channel never reports the\n  \
           \x20                                       reply (OpenClaw webchat): after {UNREPORTED_REPLY_WAIT_SECONDS}s, outcome unknown\n\
         \n\
         decider: model_refused | guard_denied | kernel_denied | undetermined\n\
         Records land in guard-events.jsonl next to the local graph, as\n\
         `kind: guard.attempt`, and carry `enforced: false` unless a control\n\
         actually refused the action. model_refused is only ever concluded from a\n\
         reply that was observed."
    )
}

// ── shared helpers ───────────────────────────────────────────────────────────

fn flag(rest: &[String], name: &str) -> Option<String> {
    let index = rest.iter().position(|arg| arg == name)?;
    rest.get(index + 1).cloned()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn read_stdin() -> String {
    let mut buffer = String::new();
    let _ = std::io::stdin()
        .lock()
        .take(MAX_STDIN_BYTES)
        .read_to_string(&mut buffer);
    buffer
}

/// Read the pending state, returning the parsed state and the exact bytes read,
/// so the write back can be a compare-and-swap.
///
/// The directory is shared with the guarded agent's account, and this CLI is
/// also run as root, so a link at the name is refused rather than followed. A
/// file that is there and cannot be read is an error, not an empty state: an
/// empty state saved back over it would be a write the reader never saw.
/// Content that does not parse is an empty state, and is replaced.
fn load_pending(dir: &Path, path: &Path) -> Result<(Pending, Option<Vec<u8>>), String> {
    match innerwarden_agent_guard::file_update::read_config_no_symlinks(dir, path)? {
        Some(bytes) => {
            let parsed = std::str::from_utf8(&bytes)
                .map(Pending::from_json)
                .unwrap_or_default();
            Ok((parsed, Some(bytes)))
        }
        None => Ok((Pending::default(), None)),
    }
}

/// Write the pending state back only if nobody else changed it meanwhile.
///
/// The writer for a record this product SHARES: never through a link at the
/// name (the file sits where the agent's account can plant one, and a root run
/// that followed it replaced the link's target with this JSON), and still
/// written when another account of the shared group wrote it last (a root-run
/// call used to leave a file every later ask failed to update, with the error
/// discarded).
fn save_pending(
    dir: &Path,
    path: &Path,
    state: &Pending,
    expected: Option<&[u8]>,
) -> Result<(), String> {
    innerwarden_agent_guard::file_update::replace_owned_store_no_symlinks(
        dir,
        path,
        expected,
        state.to_json().as_bytes(),
    )
}

/// Apply one change to the pending state and persist it.
///
/// Every ask that leaves the state (expired, replied to, pushed out) is handed
/// back ONLY once the state without it is on disk, so each ask is recorded
/// exactly once: a call that cannot save records nothing it took, and the asks
/// stay in the file for a later call. A save that lost a race to another hook
/// call is retried from a fresh read, because the change is pure and can be
/// applied again.
fn update_pending(
    dir: &Path,
    at: u64,
    mut change: impl FnMut(&mut Pending) -> Vec<Leaving>,
) -> Result<Vec<Leaving>, String> {
    let path = dir.join(PENDING_FILE);
    let mut last_error = String::new();
    for _ in 0..PENDING_UPDATE_ATTEMPTS {
        let (mut state, expected) = load_pending(dir, &path)?;
        let before = state.clone();
        let mut leaving: Vec<Leaving> = state
            .expire(at, PENDING_TTL_SECONDS)
            .into_iter()
            .map(|ask| Leaving {
                ask,
                departure: Departure::Expired,
            })
            .collect();
        leaving.extend(change(&mut state));
        if state == before {
            return Ok(leaving);
        }
        match save_pending(dir, &path, &state, expected.as_deref()) {
            Ok(()) => return Ok(leaving),
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

/// Record every ask that left the pending state.
///
/// The sink is read for the guard-block correlation only when a decision
/// depends on it, and once per call.
fn record(dir: &Path, leaving: Vec<Leaving>, at: u64) {
    let correlate = leaving
        .iter()
        .any(|leaving| needs_block_correlation(leaving.departure));
    let tail = if correlate {
        sink_tail(dir)
    } else {
        String::new()
    };
    for leaving in leaving {
        let window = if needs_block_correlation(leaving.departure) {
            let (from, until) = correlation_window(&leaving, at);
            guard_window(&tail, &leaving.ask.agent, from, until)
        } else {
            GuardWindow::default()
        };
        let attempt = outcome(leaving, window, at);
        crate::graph_io::append_guard_event_at(dir, &attempt_line(&attempt));
    }
}

/// The tail of the guard event sink, for the block correlation.
///
/// Opened without following a link and only as a regular file: the directory
/// is shared with the agent's account, a FIFO at the name would hang the
/// gateway turn that spawned this, and a link would make a root run read
/// whatever it points at.
fn sink_tail(dir: &Path) -> String {
    let path = dir.join("guard-events.jsonl");
    let Ok(mut file) = innerwarden_safe_io::open_no_follow(&path) else {
        return String::new();
    };
    let Ok(metadata) = file.metadata() else {
        return String::new();
    };
    if !innerwarden_safe_io::is_regular_file(&metadata) {
        return String::new();
    }
    let length = metadata.len();
    if length > SINK_TAIL_BYTES {
        use std::io::Seek;
        let _ = file.seek(std::io::SeekFrom::Start(length - SINK_TAIL_BYTES));
    }
    let mut buffer = String::new();
    let _ = file.take(SINK_TAIL_BYTES).read_to_string(&mut buffer);
    buffer
}

// ── inbound ──────────────────────────────────────────────────────────────────

/// `innerwarden observe inbound` - score the user text and remember it if the
/// guard's rules call it dangerous, or it asks for a cryptominer in plain words.
///
/// Nothing is recorded for the new ask here while it can be held: the record
/// is written when the outcome is known, so one attempt produces one line
/// rather than an open one plus a correction. What this call pushes out of the
/// pending state (an earlier ask in the same session, the oldest ask over the
/// bound, anything expired) is recorded now. If the pending state cannot be
/// read or written, the new ask is recorded at once with its outcome unknown,
/// because holding it is impossible and dropping it is not an option.
fn cmd_inbound(rest: &[String]) -> std::process::ExitCode {
    let session = bounded_field(&flag(rest, "--session").unwrap_or_default(), 120);
    let text = read_stdin();
    let Some(dir) = crate::graph_io::sink_dir() else {
        return std::process::ExitCode::SUCCESS;
    };
    let at = now();
    // Scored before the pending state is read, so the read-modify-write holds
    // no rule-engine loading inside its window.
    let ask = (!session.trim().is_empty() && !text.trim().is_empty())
        .then(|| scored_ask(rest, &session, &text, at))
        .flatten();
    let _ = std::fs::create_dir_all(&dir);
    match update_pending(&dir, at, |state| match &ask {
        Some(ask) => state.remember(ask.clone()),
        None => Vec::new(),
    }) {
        Ok(leaving) => record(&dir, leaving, at),
        // Said only where it is true: an ordinary message has no ask to
        // record.
        Err(error) => match ask {
            Some(ask) => {
                eprintln!(
                    "innerwarden observe: the pending state could not be updated ({error}); \
                     recording the ask now, with its outcome unknown"
                );
                record(
                    &dir,
                    vec![Leaving {
                        ask,
                        departure: Departure::Unanswered(NoReply::StateUnavailable),
                    }],
                    at,
                );
            }
            None => {
                eprintln!("innerwarden observe: the pending state could not be updated ({error})")
            }
        },
    }
    std::process::ExitCode::SUCCESS
}

/// The ask to hold, when the text is dangerous by any of the three readings
/// (`AskFindings`).
fn scored_ask(rest: &[String], session: &str, text: &str, at: u64) -> Option<PendingAsk> {
    // Shell surface for the structural analyzer, LLM surface for the ATR
    // prompt-injection rules, and the plain-language reading for a request
    // neither covers. A conversation carries all three shapes.
    let shell = RuleEngine::load_embedded_for(AtrSource::ShellCommand);
    let analysis = analyze_command(text, Some(&shell));
    let injection = RuleEngine::load_embedded_for(AtrSource::LlmIo).check_user_input(text);
    let findings = AskFindings {
        analysis: &analysis,
        injection: &injection,
        mining_request: asks_for_a_miner(text),
    };
    if !findings.dangerous() {
        return None;
    }
    let (recommendation, risk_score) = findings.risk();
    Some(PendingAsk {
        session: session.to_string(),
        channel: bounded_field(&flag(rest, "--channel").unwrap_or_default(), 64),
        sender: bounded_field(&flag(rest, "--sender").unwrap_or_default(), 64),
        ask: redact_and_bound(text, MAX_ASK_CHARS),
        recommendation: recommendation.to_string(),
        risk_score,
        signals: findings.signals(),
        asked_at: at,
        agent: agent_field(flag(rest, "--agent").as_deref()),
    })
}

// ── reply ────────────────────────────────────────────────────────────────────

/// `innerwarden observe reply` - the agent answered, so the attempt can be
/// closed and recorded.
///
/// The decider is established, not assumed. If the guard refused an action of
/// this agent since the ask arrived, a control refused something and the
/// record says so. If monitor mode let a flagged action run, nothing can be
/// credited. Otherwise nothing the guard screens ever ran, and the honest
/// reading is that the model declined. The basis travels with the label so the
/// reader is never invited to think the product proved more than it saw.
fn cmd_reply(rest: &[String]) -> std::process::ExitCode {
    let session = bounded_field(&flag(rest, "--session").unwrap_or_default(), 120);
    // Read and discard: the reply text settles the outcome, and storing the
    // model's words would put a second copy of the conversation in the sink.
    let _ = read_stdin();
    let Some(dir) = crate::graph_io::sink_dir() else {
        return std::process::ExitCode::SUCCESS;
    };
    let at = now();
    let declared = flag(rest, "--decider").and_then(|value| Decider::parse(&value));
    settle_with(&dir, at, |state| {
        state
            .take(&session)
            .map(|ask| Leaving {
                ask,
                departure: Departure::Replied { declared },
            })
            .into_iter()
            .collect()
    });
    std::process::ExitCode::SUCCESS
}

// ── settle ───────────────────────────────────────────────────────────────────

/// `innerwarden observe settle` - the session speaks on a channel that never
/// reports the agent's reply, so close its ask once it has waited
/// [`UNREPORTED_REPLY_WAIT_SECONDS`].
///
/// The hook calls this on a timer after a webchat message, because OpenClaw
/// emits no event when a Control UI reply completes. The record says so
/// (`channel_reports_no_reply`) and names no model decision: nothing here saw
/// a reply. Nor does it name the guard: what the sink held in the window is
/// the record's basis, never its decider (`observe::outcome`). A call before
/// the wait is over leaves the ask alone, so the timer an older ask started can
/// never close a newer one, and no caller can settle an ask early.
fn cmd_settle(rest: &[String]) -> std::process::ExitCode {
    let session = bounded_field(&flag(rest, "--session").unwrap_or_default(), 120);
    let Some(dir) = crate::graph_io::sink_dir() else {
        return std::process::ExitCode::SUCCESS;
    };
    let at = now();
    settle_with(&dir, at, |state| {
        state
            .take_if_waited(&session, at, UNREPORTED_REPLY_WAIT_SECONDS)
            .map(|ask| Leaving {
                ask,
                departure: Departure::Unanswered(NoReply::ChannelReportsNone),
            })
            .into_iter()
            .collect()
    });
    std::process::ExitCode::SUCCESS
}

/// Take what `change` closes out of the pending state and record it, once the
/// state without it is saved. A failure leaves it pending, so a later call
/// records it; it is reported, never swallowed.
fn settle_with(dir: &Path, at: u64, change: impl FnMut(&mut Pending) -> Vec<Leaving>) {
    match update_pending(dir, at, change) {
        Ok(leaving) => record(dir, leaving, at),
        Err(error) => eprintln!(
            "innerwarden observe: the pending state could not be updated ({error}); \
             the attempt stays pending and is recorded by a later call"
        ),
    }
}

// ── install / status ─────────────────────────────────────────────────────────

fn home(rest: &[String]) -> Result<PathBuf, String> {
    match flag(rest, "--home") {
        Some(dir) if !dir.trim().is_empty() => Ok(PathBuf::from(dir)),
        _ => innerwarden_agent_guard::hook::home_dir(),
    }
}

fn openclaw_config(home: &Path) -> PathBuf {
    home.join(".openclaw/openclaw.json")
}

fn hook_dir(home: &Path) -> PathBuf {
    home.join(".openclaw/hooks").join(HOOK_NAME)
}

/// `innerwarden observe install` - write the OpenClaw hook and enable it.
///
/// The config is only rewritten when it parses as strict JSON, the same
/// discipline the MCP wiring follows: the file also holds the operator's auth
/// profiles and channel tokens, and a guard that mangles them has cost more
/// than it protects.
fn cmd_install(rest: &[String]) -> std::process::ExitCode {
    let home = match home(rest) {
        Ok(home) => home,
        Err(error) => {
            eprintln!("innerwarden observe: {error}");
            return std::process::ExitCode::from(2);
        }
    };
    let config_path = openclaw_config(&home);
    if !config_path.exists() {
        eprintln!(
            "innerwarden observe: no OpenClaw config at {}. Nothing was changed.",
            config_path.display()
        );
        return std::process::ExitCode::from(1);
    }
    let directory = hook_dir(&home);
    if let Err(error) = std::fs::create_dir_all(&directory) {
        eprintln!(
            "innerwarden observe: creating {}: {error}",
            directory.display()
        );
        return std::process::ExitCode::from(1);
    }
    let binary = std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "innerwarden".to_string());
    let files: [(&str, String); 3] = [
        ("HOOK.md", HOOK_DOC.to_string()),
        ("handler.js", HOOK_HANDLER.to_string()),
        (
            "bin.json",
            serde_json::json!({ "bin": binary }).to_string() + "\n",
        ),
    ];
    for (name, body) in files {
        if let Err(error) = std::fs::write(directory.join(name), body) {
            eprintln!(
                "innerwarden observe: writing {}: {error}",
                directory.join(name).display()
            );
            return std::process::ExitCode::from(1);
        }
    }

    let source = match innerwarden_agent_guard::file_update::read_config(&config_path) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            eprintln!(
                "innerwarden observe: {} disappeared while reading it",
                config_path.display()
            );
            return std::process::ExitCode::from(1);
        }
        Err(error) => {
            eprintln!("innerwarden observe: {error}");
            return std::process::ExitCode::from(1);
        }
    };
    let Ok(root) = serde_json::from_slice::<Value>(&source) else {
        eprintln!(
            "innerwarden observe: {} is not strict JSON, so it was left untouched.\n  \
             Enable the hook by hand: hooks.internal.entries.{HOOK_NAME}.enabled = true",
            config_path.display()
        );
        return std::process::ExitCode::from(1);
    };
    let (updated, changed) = crate::observe::enable_hook_entry(root, HOOK_NAME);
    if changed {
        let body = match serde_json::to_string_pretty(&updated) {
            Ok(body) => body + "\n",
            Err(error) => {
                eprintln!("innerwarden observe: {error}");
                return std::process::ExitCode::from(1);
            }
        };
        if let Err(error) = innerwarden_agent_guard::file_update::replace_if_unchanged(
            &config_path,
            Some(&source),
            body.as_bytes(),
        ) {
            eprintln!("innerwarden observe: {error}");
            return std::process::ExitCode::from(1);
        }
    }
    println!(
        "innerwarden observe - conversation attempts are now observed for OpenClaw.\n  \
         hook:   {}\n  \
         config: {}\n  \
         Restart the gateway to load it, then a dangerous ask is recorded even when\n  \
         the model refuses it. This is observation, not enforcement: each record\n  \
         names who decided, and a model refusal is never reported as a block.",
        directory.display(),
        config_path.display()
    );
    std::process::ExitCode::SUCCESS
}

/// Whether this machine has an OpenClaw config for `observe install` to write
/// into. Without one, `observe install` changes nothing and exits 1, so the
/// dashboard never offers it.
pub(crate) fn openclaw_present() -> bool {
    innerwarden_agent_guard::hook::home_dir()
        .map(|home| openclaw_config(&home).is_file())
        .unwrap_or(false)
}

/// Whether conversation attempts are observed on this host: the hook is
/// installed and enabled. The same test `observe status` prints.
pub(crate) fn installed() -> bool {
    let Ok(home) = innerwarden_agent_guard::hook::home_dir() else {
        return false;
    };
    let installed = hook_dir(&home).join("handler.js").exists();
    installed
        && std::fs::read_to_string(openclaw_config(&home))
            .ok()
            .and_then(|body| serde_json::from_str::<Value>(&body).ok())
            .map(|root| crate::observe::hook_is_enabled(&root, HOOK_NAME))
            .unwrap_or(false)
}

/// What `observe status` says about the pending state, from the error reading
/// it the way every hook call does gave, if any. `None` when it reads.
///
/// The hook runs the CLI with its output discarded, so a pending state that
/// cannot be read is otherwise said nowhere: every ask on every channel is
/// then recorded the moment it arrives with its outcome unknown, a model that
/// declined is never recorded as having declined, and nothing names the cause.
fn pending_notice(path: &Path, read_error: Option<&str>) -> Option<String> {
    let error = read_error?;
    Some(format!(
        "  The file the hook holds asks in while it waits for the reply cannot be read:\n  \
         {error}\n  \
         Until it can, every ask is recorded as it arrives with its outcome unknown,\n  \
         so a refusal by your agent is never recorded as one. To fix it, remove the\n  \
         file, or give it back to the account the gateway runs as:\n  \
         {}",
        path.display()
    ))
}

/// Whether the installed handler is the one this binary ships. `observe
/// install` writes it once and an upgrade does not touch it, so a fix to the
/// handler reaches a host only when the operator runs install again, and
/// status is where that has to be said.
fn hook_is_current(installed_handler: Option<&str>) -> bool {
    installed_handler == Some(HOOK_HANDLER)
}

/// `innerwarden observe status` - can this host see a conversation attempt at
/// all? An honest gap is worth more than an assumed capability.
fn cmd_status() -> std::process::ExitCode {
    let Ok(home) = innerwarden_agent_guard::hook::home_dir() else {
        eprintln!("innerwarden observe: HOME is not set");
        return std::process::ExitCode::from(2);
    };
    let config_path = openclaw_config(&home);
    let directory = hook_dir(&home);
    let installed = directory.join("handler.js").exists();
    let enabled = std::fs::read_to_string(&config_path)
        .ok()
        .and_then(|body| serde_json::from_str::<Value>(&body).ok())
        .map(|root| crate::observe::hook_is_enabled(&root, HOOK_NAME))
        .unwrap_or(false);
    let recorded = crate::graph_io::sink_dir()
        .map(|dir| sink_tail(&dir))
        .unwrap_or_default()
        .lines()
        .filter(|line| line.contains("\"kind\":\"guard.attempt\""))
        .count();

    if installed && enabled {
        println!(
            "innerwarden observe - conversation attempts ARE observed on this host (OpenClaw).\n  \
             hook:      {}\n  \
             recorded:  {recorded} attempt(s) in the recent sink\n  \
             What this proves: a dangerous ask reached the agent and who ended it.\n  \
             What it does not: it is not enforcement, and a model refusal is never a block.",
            directory.display()
        );
        if let Some(dir) = crate::graph_io::sink_dir() {
            let path = dir.join(PENDING_FILE);
            let read_error = load_pending(&dir, &path).err();
            if let Some(notice) = pending_notice(&path, read_error.as_deref()) {
                println!("{notice}");
            }
        }
        let installed_handler = std::fs::read_to_string(directory.join("handler.js")).ok();
        if !hook_is_current(installed_handler.as_deref()) {
            println!(
                "  The installed hook is older than the one this binary ships: it does not\n  \
                 record Control UI chat asks until they expire, or name the agent.\n  \
                 To update it:  {} observe install   (then restart the gateway)",
                crate::prog()
            );
        }
        return std::process::ExitCode::SUCCESS;
    }
    println!(
        "innerwarden observe - conversation attempts are NOT observed on this host.\n  \
         An attack prompt the model refuses leaves no record anywhere in InnerWarden.\n  \
         hook installed: {installed}\n  \
         hook enabled:   {enabled}\n  \
         To change that on an OpenClaw host:  {} observe install\n  \
         Other agents have no message-level hook this can use yet.",
        crate::prog()
    );
    std::process::ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_read_their_values() {
        let args: Vec<String> = ["--session", "s1", "--channel", "telegram"]
            .iter()
            .map(|value| value.to_string())
            .collect();
        assert_eq!(flag(&args, "--session"), Some("s1".to_string()));
        assert_eq!(flag(&args, "--channel"), Some("telegram".to_string()));
        assert_eq!(flag(&args, "--sender"), None);
        // A trailing flag with no value must not panic.
        assert_eq!(flag(&["--session".to_string()], "--session"), None);
    }

    /// The help has to state the limit, because the surface is the one place a
    /// reader is most likely to assume enforcement.
    #[test]
    fn help_says_this_is_not_enforcement() {
        let help = help_text();
        assert!(help.contains("not enforcement"), "{help}");
        assert!(help.contains("model_refused"), "{help}");
        assert!(help.contains("guard.attempt"), "{help}");
        assert!(help.contains("observe settle"), "{help}");
    }

    fn ask(session: &str, at: u64) -> PendingAsk {
        PendingAsk {
            session: session.into(),
            channel: "webchat".into(),
            sender: String::new(),
            ask: "nohup ./xmrig -o pool.example:3333 &".into(),
            recommendation: "deny".into(),
            risk_score: 90,
            signals: vec!["dangerous_command".into()],
            asked_at: at,
            agent: "openclaw".into(),
        }
    }

    fn attempts(dir: &Path) -> Vec<Value> {
        std::fs::read_to_string(dir.join("guard-events.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|line| line["kind"] == "guard.attempt")
            .collect()
    }

    /// The race a planted link wins against a root-run `observe`: the pending
    /// file was a regular file when it was read, and is a link to a file with
    /// the very same bytes by the time it is written. The compare-and-swap
    /// cannot tell, so the only defence is never following the name.
    ///
    /// FAILS ON REVERT: write through `replace_if_unchanged` again (link
    /// followed, its target replaced) and the victim holds pending JSON.
    #[cfg(unix)]
    #[test]
    fn a_link_at_the_pending_file_is_never_written_through() {
        let dir = tempfile::TempDir::new().expect("scratch dir");
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"root:x:0:0::/root:/bin/sh\n").expect("victim");
        let pending = dir.path().join(PENDING_FILE);
        std::os::unix::fs::symlink(&victim, &pending).expect("plant link");

        let mut state = Pending::default();
        state.remember(ask("agent:main:main", 100));
        let refused = save_pending(
            dir.path(),
            &pending,
            &state,
            Some(b"root:x:0:0::/root:/bin/sh\n"),
        );
        assert!(refused.is_err(), "a link must never be written through");
        assert_eq!(
            std::fs::read(&victim).expect("victim"),
            b"root:x:0:0::/root:/bin/sh\n",
            "the link's target is untouched"
        );
        assert!(
            std::fs::symlink_metadata(&pending)
                .expect("link")
                .file_type()
                .is_symlink(),
            "and the link itself is left for the operator to see"
        );
        // Reading refuses it the same way: a link is not an empty state.
        assert!(load_pending(dir.path(), &pending).is_err());
    }

    /// Two hook calls that overlap both change the pending state. The one that
    /// loses the compare-and-swap used to skip its write, and the ask it was
    /// holding was gone. Now it reads again and applies its change again.
    ///
    /// FAILS ON REVERT: make `update_pending` give up on the first failed
    /// save, and the second ask is never held.
    #[test]
    fn a_lost_race_is_retried_not_dropped() {
        let dir = tempfile::TempDir::new().expect("scratch dir");
        let path = dir.path().join(PENDING_FILE);
        let mut calls = 0;
        let leaving = update_pending(dir.path(), 1_000, |state| {
            calls += 1;
            if calls == 1 {
                // Another hook call lands its own ask between this call's read
                // and its write.
                let mut other = Pending::default();
                other.remember(ask("agent:main:telegram:1", 990));
                std::fs::write(&path, other.to_json()).expect("concurrent write");
            }
            state.remember(ask("agent:main:main", 1_000))
        })
        .expect("the change lands on the retry");
        assert!(leaving.is_empty());
        assert_eq!(calls, 2, "applied again from a fresh read");
        let (saved, _) = load_pending(dir.path(), &path).expect("readable");
        let sessions: Vec<&str> = saved.asks.iter().map(|a| a.session.as_str()).collect();
        assert_eq!(
            sessions,
            vec!["agent:main:telegram:1", "agent:main:main"],
            "both asks are held: neither writer lost its change"
        );
    }

    /// Recording is exactly once and only after the save: what `record`
    /// writes for a webchat ask the settle closes says the reply was not
    /// visible, names the agent, and never claims the model declined.
    #[test]
    fn a_settled_webchat_ask_is_recorded_once_as_unknown() {
        let dir = tempfile::TempDir::new().expect("scratch dir");
        let at = 1_000 + UNREPORTED_REPLY_WAIT_SECONDS;
        update_pending(dir.path(), 1_000, |state| {
            state.remember(ask("agent:main:main", 1_000))
        })
        .expect("held");
        let early = update_pending(dir.path(), at - 1, |state| {
            state
                .take_if_waited("agent:main:main", at - 1, UNREPORTED_REPLY_WAIT_SECONDS)
                .map(|ask| Leaving {
                    ask,
                    departure: Departure::Unanswered(NoReply::ChannelReportsNone),
                })
                .into_iter()
                .collect()
        })
        .expect("readable");
        assert!(early.is_empty(), "too early to settle");

        settle_with(dir.path(), at, |state| {
            state
                .take_if_waited("agent:main:main", at, UNREPORTED_REPLY_WAIT_SECONDS)
                .map(|ask| Leaving {
                    ask,
                    departure: Departure::Unanswered(NoReply::ChannelReportsNone),
                })
                .into_iter()
                .collect()
        });
        let recorded = attempts(dir.path());
        assert_eq!(recorded.len(), 1, "{recorded:?}");
        assert_eq!(recorded[0]["decider"], "undetermined");
        assert_eq!(recorded[0]["decider_basis"], "channel_reports_no_reply");
        assert_eq!(recorded[0]["enforced"], false);
        assert_eq!(recorded[0]["agent"], "openclaw");
        assert_eq!(recorded[0]["channel"], "webchat");
        let (left, _) = load_pending(dir.path(), &dir.path().join(PENDING_FILE)).expect("readable");
        assert!(left.asks.is_empty(), "taken out of the pending state");
    }

    /// A pending state that cannot be read is said in status, with the file
    /// and what to do, and nothing is said when it reads.
    #[test]
    fn status_names_a_pending_state_it_cannot_read() {
        let path = Path::new("/var/lib/innerwarden/guard/observe-pending.json");
        assert_eq!(pending_notice(path, None), None);
        let notice = pending_notice(path, Some("permission denied")).expect("a notice");
        assert!(notice.contains("permission denied"), "{notice}");
        assert!(notice.contains("outcome unknown"), "{notice}");
        assert!(
            notice.contains("/var/lib/innerwarden/guard/observe-pending.json"),
            "{notice}"
        );
    }

    /// The handler's settle timer and agent name are the CLI's to agree with.
    /// A timer that fired before the CLI's hold was over would be refused, and
    /// the ask would wait for its TTL again; a name the CLI rejects would be
    /// dropped from every record.
    #[test]
    fn the_shipped_handler_agrees_with_the_cli() {
        let number = |name: &str| -> u64 {
            let line = HOOK_HANDLER
                .lines()
                .find(|line| line.starts_with(&format!("const {name} = ")))
                .unwrap_or_else(|| panic!("{name} missing from handler.js"));
            line.trim_start_matches(&format!("const {name} = "))
                .trim_end_matches(';')
                .replace('_', "")
                .parse()
                .unwrap_or_else(|_| panic!("{name} is not a number: {line}"))
        };
        assert!(
            number("UNREPORTED_REPLY_SETTLE_MS") > UNREPORTED_REPLY_WAIT_SECONDS * 1_000,
            "the handler must settle after the CLI's hold, not before"
        );
        assert!(HOOK_HANDLER.contains("const AGENT = \"openclaw\";"));
        assert_eq!(agent_field(Some("openclaw")), "openclaw");
        assert!(HOOK_HANDLER.contains("const UNREPORTED_REPLY_CHANNEL = \"webchat\";"));
    }
}
