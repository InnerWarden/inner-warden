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
    attempt_line, bounded_field, dangerous, guard_block_since, redact_and_bound, signal_names,
    Attempt, Basis, Decider, Pending, PendingAsk, MAX_ASK_CHARS, PENDING_TTL_SECONDS,
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

const HOOK_DOC: &str = include_str!("../assets/openclaw-hook/HOOK.md");
const HOOK_HANDLER: &str = include_str!("../assets/openclaw-hook/handler.js");

pub fn cmd(rest: &[String]) -> std::process::ExitCode {
    match rest.first().map(String::as_str) {
        Some("inbound") => cmd_inbound(&rest[1..]),
        Some("reply") => cmd_reply(&rest[1..]),
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
           {prog} observe inbound --session <k> [--channel <c>] [--sender <s>]\n  \
           \x20                                       score the user text on stdin\n  \
           {prog} observe reply --session <k> [--channel <c>] [--decider <d>]\n  \
           \x20                                       close the attempt the session was waiting on\n\
         \n\
         decider: model_refused | guard_denied | kernel_denied | undetermined\n\
         Records land in guard-events.jsonl next to the local graph, as\n\
         `kind: guard.attempt`, and carry `enforced: false` unless a control\n\
         actually refused the action."
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

fn pending_path() -> Option<PathBuf> {
    crate::graph_io::sink_dir().map(|dir| dir.join("observe-pending.json"))
}

/// Read the pending file, returning the parsed state and the exact bytes read,
/// so the write back can be a compare-and-swap.
fn load_pending(path: &Path) -> (Pending, Option<Vec<u8>>) {
    match innerwarden_agent_guard::file_update::read_config(path) {
        Ok(Some(bytes)) => {
            let parsed = std::str::from_utf8(&bytes)
                .map(Pending::from_json)
                .unwrap_or_default();
            (parsed, Some(bytes))
        }
        _ => (Pending::default(), None),
    }
}

/// Write the pending state back only if nobody else changed it meanwhile.
///
/// Two hook invocations can overlap on a busy gateway. A lost update costs one
/// unpaired attempt record; a torn file would cost every pending attempt, so
/// the write is a compare-and-swap and a conflict is simply skipped.
fn save_pending(path: &Path, state: &Pending, expected: Option<&[u8]>) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = innerwarden_agent_guard::file_update::replace_if_unchanged(
        path,
        expected,
        state.to_json().as_bytes(),
    );
}

/// Record every attempt whose reply never arrived. Called on both hook paths so
/// a stale entry always lands eventually: a gateway restart must not be a way
/// to make an attempt disappear.
fn flush_expired(state: &mut Pending, at: u64) -> usize {
    let expired = state.expire(at, PENDING_TTL_SECONDS);
    for ask in &expired {
        write_attempt(&Attempt {
            ask: ask.clone(),
            recorded_at: at,
            decider: Decider::Undetermined,
            basis: Basis::NoReplyWithinTtl,
        });
    }
    expired.len()
}

fn write_attempt(attempt: &Attempt) {
    crate::graph_io::append_guard_event(&attempt_line(attempt));
}

/// The tail of the guard event sink, for the block correlation.
fn sink_tail() -> String {
    let Some(path) = crate::graph_io::sink_dir().map(|dir| dir.join("guard-events.jsonl")) else {
        return String::new();
    };
    let Ok(mut file) = std::fs::File::open(&path) else {
        return String::new();
    };
    let length = file.metadata().map(|meta| meta.len()).unwrap_or(0);
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
/// guard's own rule engine calls it dangerous.
///
/// Nothing is recorded here. The record is written when the outcome is known,
/// so one attempt produces one line rather than an open one plus a correction.
fn cmd_inbound(rest: &[String]) -> std::process::ExitCode {
    let session = bounded_field(&flag(rest, "--session").unwrap_or_default(), 120);
    let text = read_stdin();
    let Some(path) = pending_path() else {
        return std::process::ExitCode::SUCCESS;
    };
    let at = now();
    let (mut state, expected) = load_pending(&path);
    let flushed = flush_expired(&mut state, at);

    if session.trim().is_empty() || text.trim().is_empty() {
        if flushed > 0 {
            save_pending(&path, &state, expected.as_deref());
        }
        return std::process::ExitCode::SUCCESS;
    }

    // Shell surface for the structural analyzer, LLM surface for the ATR
    // prompt-injection rules. A conversation carries both shapes.
    let shell = RuleEngine::load_embedded_for(AtrSource::ShellCommand);
    let analysis = analyze_command(&text, Some(&shell));
    let injection = RuleEngine::load_embedded_for(AtrSource::LlmIo).check_user_input(&text);

    if !dangerous(&analysis, &injection) {
        if flushed > 0 {
            save_pending(&path, &state, expected.as_deref());
        }
        return std::process::ExitCode::SUCCESS;
    }

    state.remember(PendingAsk {
        session: session.clone(),
        channel: bounded_field(&flag(rest, "--channel").unwrap_or_default(), 64),
        sender: bounded_field(&flag(rest, "--sender").unwrap_or_default(), 64),
        ask: redact_and_bound(&text, MAX_ASK_CHARS),
        recommendation: analysis.recommendation.clone(),
        risk_score: analysis.risk_score,
        signals: signal_names(&analysis, &injection),
        asked_at: at,
    });
    save_pending(&path, &state, expected.as_deref());
    std::process::ExitCode::SUCCESS
}

// ── reply ────────────────────────────────────────────────────────────────────

/// `innerwarden observe reply` - the agent answered, so the attempt can be
/// closed and recorded.
///
/// The decider is established, not assumed. If the guard recorded a block since
/// the ask arrived, a control refused something and the record says so.
/// Otherwise nothing the guard screens ever ran, and the honest reading is that
/// the model declined. The basis travels with the label so the reader is never
/// invited to think the product proved more than it saw.
fn cmd_reply(rest: &[String]) -> std::process::ExitCode {
    let session = bounded_field(&flag(rest, "--session").unwrap_or_default(), 120);
    // Read and discard: the reply text settles the outcome, and storing the
    // model's words would put a second copy of the conversation in the sink.
    let _ = read_stdin();
    let Some(path) = pending_path() else {
        return std::process::ExitCode::SUCCESS;
    };
    let at = now();
    let (mut state, expected) = load_pending(&path);
    let flushed = flush_expired(&mut state, at);
    let Some(ask) = state.take(&session) else {
        if flushed > 0 {
            save_pending(&path, &state, expected.as_deref());
        }
        return std::process::ExitCode::SUCCESS;
    };

    let declared = flag(rest, "--decider").and_then(|value| Decider::parse(&value));
    let (decider, basis) = match declared {
        Some(decider) => (decider, Basis::Declared),
        None if guard_block_since(&sink_tail(), ask.asked_at) => {
            (Decider::GuardDenied, Basis::GuardBlockInWindow)
        }
        None => (Decider::ModelRefused, Basis::NoScreenedExecution),
    };
    write_attempt(&Attempt {
        ask,
        recorded_at: at,
        decider,
        basis,
    });
    save_pending(&path, &state, expected.as_deref());
    std::process::ExitCode::SUCCESS
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
    let recorded = sink_tail()
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
    }
}
