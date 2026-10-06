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

use innerwarden_agent_guard::file_update::ReplaceError;
use innerwarden_agent_guard::rules::{AtrSource, RuleEngine};
use serde_json::Value;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::observe::{
    agent_field, asks_for_a_miner, attempt_line, bounded_field, conversation_analysis,
    correlation_window, enable_plugin_entry, guard_window, installed_files, message_id_field,
    needs_block_correlation, outcome, plugin_blocker, redact_and_bound, AskFindings, Decider,
    Departure, GuardWindow, InstalledFiles, Leaving, NoReply, Pending, PendingAsk, PluginBlocker,
    PluginEntry, ShippedFile, TurnEnd, MAX_ASK_CHARS, PENDING_TTL_SECONDS,
    UNREPORTED_REPLY_WAIT_SECONDS,
};

/// The hook directory name inside `~/.openclaw/hooks/`, and the config key that
/// enables it. OpenClaw derives the config key from the hook name.
const HOOK_NAME: &str = "innerwarden-attempts";

/// The reply plugin's id: its directory inside `~/.openclaw/extensions/`, and
/// its key under `plugins.entries`.
const PLUGIN_ID: &str = "innerwarden-replies";

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

/// How long one save of the pending state waits for another writer that holds
/// its update lock.
///
/// A real writer is another hook call, which holds it for one small write.
/// Anyone else who can open the lock beside the shared record (the agent's
/// own account included) could hold it for as long as they liked, and the
/// save waited the whole time, until the OpenClaw hook killed the call at its
/// 4 s cap with the ask it carried unrecorded. Bounded well under that cap, a
/// held lock costs one wait and the ask is still recorded.
const PENDING_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

const HOOK_DOC: &str = include_str!("../assets/openclaw-hook/HOOK.md");
const HOOK_HANDLER: &str = include_str!("../assets/openclaw-hook/handler.js");
const PLUGIN_ENTRY: &str = include_str!("../assets/openclaw-plugin/index.js");
const PLUGIN_MANIFEST: &str = include_str!("../assets/openclaw-plugin/openclaw.plugin.json");
const PLUGIN_PACKAGE: &str = include_str!("../assets/openclaw-plugin/package.json");

/// The message hook's files, `handler.js` first: it being there is what makes
/// the hook installed. The earlier digests are the bodies Community 1.2.0
/// through 1.5.1 shipped (one each, unchanged across those releases), read
/// from the release tags. When a release changes a file, the digest of the
/// body it replaces goes here: `the_shipped_files_are_the_pinned_ones` fails
/// until it does.
const HOOK_FILES: [ShippedFile; 2] = [
    ShippedFile {
        name: "handler.js",
        body: HOOK_HANDLER,
        earlier: &["d58c13d9d2f481f773d81c484474468e9233369efd4d49539cad7166ca6673d9"],
    },
    ShippedFile {
        name: "HOOK.md",
        body: HOOK_DOC,
        earlier: &["6e99a2648f690360b5c4bcebcb577b61445e0859f7e883003b76d772d45610dc"],
    },
];

/// The reply plugin's files, its entry first. No earlier release shipped it.
const PLUGIN_FILES: [ShippedFile; 3] = [
    ShippedFile {
        name: "index.js",
        body: PLUGIN_ENTRY,
        earlier: &[],
    },
    ShippedFile {
        name: "openclaw.plugin.json",
        body: PLUGIN_MANIFEST,
        earlier: &[],
    },
    ShippedFile {
        name: "package.json",
        body: PLUGIN_PACKAGE,
        earlier: &[],
    },
];

pub fn cmd(rest: &[String]) -> std::process::ExitCode {
    match rest.first().map(String::as_str) {
        Some("inbound") => cmd_inbound(&rest[1..]),
        Some("reply") => cmd_reply(&rest[1..]),
        Some("settle") => cmd_settle(&rest[1..]),
        Some("ended") => cmd_ended(&rest[1..]),
        Some("install") => cmd_install(&rest[1..]),
        Some("refresh") => cmd_refresh(&rest[1..]),
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
           {prog} observe install [--home <dir>]    wire it into OpenClaw (message hook and\n  \
           \x20                                       the reply plugin for the Control UI chat)\n  \
           {prog} observe refresh [--home <dir>]    bring what install wrote up to this version,\n  \
           \x20                                       where nobody changed it (upgrade runs this)\n  \
           {prog} observe inbound --session <k> [--channel <c>] [--sender <s>] [--agent <a>]\n  \
           \x20                       [--message <id>]   score the user text on stdin\n  \
           {prog} observe reply --session <k> [--channel <c>] [--decider <d>]\n  \
           \x20                                       close the attempt the session was waiting on\n  \
           {prog} observe ended --session <k> --run <id> --turn <replied|used_tools|no_reply>\n  \
           \x20                                       close the ask that started turn <id>, as the\n  \
           \x20                                       reply plugin saw the turn end\n  \
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
) -> Result<(), ReplaceError> {
    innerwarden_agent_guard::file_update::replace_owned_store_no_symlinks(
        dir,
        path,
        expected,
        state.to_json().as_bytes(),
        PENDING_LOCK_WAIT,
    )
}

/// Apply one change to the pending state and persist it.
///
/// Every ask that leaves the state (expired, replied to, pushed out) is handed
/// back ONLY once the state without it is on disk, so each ask is recorded
/// exactly once: a call that cannot save records nothing it took, and the asks
/// stay in the file for a later call. A save that lost a race to another hook
/// call is retried from a fresh read, because the change is pure and can be
/// applied again. A save that found the lock held for its whole wait is not:
/// another attempt would only wait again, and the caller has a path for an
/// ask it cannot hold.
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
            Err(error @ ReplaceError::LockBusy { .. }) => return Err(error.to_string()),
            Err(error) => last_error = error.to_string(),
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
            guard_window(&tail, &leaving.ask.agent, &leaving.ask.session, from, until)
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
    // neither covers. A conversation carries all three shapes. The analyzer
    // reads the message as a person wrote it: a miner name that is only
    // talked about is not a command (`observe::conversation_analysis`).
    let shell = RuleEngine::load_embedded_for(AtrSource::ShellCommand);
    let analysis = conversation_analysis(text, &shell);
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
        message: message_id_field(flag(rest, "--message").as_deref()),
    })
}

// ── reply ────────────────────────────────────────────────────────────────────

/// `innerwarden observe reply` - the agent answered, so the attempt can be
/// closed and recorded.
///
/// The decider is established, not assumed. If the guard refused an action of
/// this agent in this session since the ask arrived, a control refused
/// something and the record says so; a refusal the guard recorded under
/// another session (the MCP proxy's own, or another chat's) is reported as
/// being in the window and credits no one. If monitor mode let a flagged
/// action run, nothing can be credited. Otherwise nothing the guard screens
/// ever ran, and the honest reading is that the model declined. The basis
/// travels with the label so the reader is never invited to think the product
/// proved more than it saw.
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
/// emits no internal hook event when a Control UI reply completes. Where the
/// reply plugin reported the turn's end first (`observe ended`), the ask is
/// already closed and this finds nothing. Otherwise the record says so
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

// ── ended ────────────────────────────────────────────────────────────────────

/// `innerwarden observe ended` - the agent's turn that an ask started is over,
/// and `--turn` says how it ended. The reply plugin calls this from OpenClaw's
/// `agent_end` hook for a Control UI turn, which the message hook never sees
/// end.
///
/// Only the ask whose message started THIS turn is closed (`--run`, matched
/// against the id the message hook recorded with it), so a turn still
/// answering an earlier message never closes a newer ask. Nothing held for
/// the run: nothing to do, and the message hook's timer settles an ask that
/// arrives later. A turn that replied with no tool call is a reply like any
/// other: what the guard recorded in the turn still decides first
/// (`observe::outcome`). One that called a tool, or ended with nothing said,
/// is recorded with its outcome unknown and that as its reason.
///
/// Anything that can run this CLI as the agent's account can call it, as it
/// can call `observe reply`: a conversation record is evidence of what the
/// model did, never of enforcement, and a call here can no more credit the
/// guard than a reply can.
fn cmd_ended(rest: &[String]) -> std::process::ExitCode {
    let Some(turn) = flag(rest, "--turn").and_then(|value| TurnEnd::parse(&value)) else {
        eprintln!("innerwarden observe ended: --turn must be replied, used_tools or no_reply");
        return std::process::ExitCode::from(2);
    };
    let session = bounded_field(&flag(rest, "--session").unwrap_or_default(), 120);
    let run = message_id_field(flag(rest, "--run").as_deref());
    if session.trim().is_empty() || run.is_empty() {
        return std::process::ExitCode::SUCCESS;
    }
    let Some(dir) = crate::graph_io::sink_dir() else {
        return std::process::ExitCode::SUCCESS;
    };
    let at = now();
    settle_with(&dir, at, |state| {
        state
            .take_for_run(&session, &run)
            .map(|ask| Leaving {
                ask,
                departure: Departure::TurnEnded(turn),
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

/// Where OpenClaw discovers a plugin it was not installed through its own
/// CLI: a package directory under `~/.openclaw/extensions/`.
fn plugin_dir(home: &Path) -> PathBuf {
    home.join(".openclaw/extensions").join(PLUGIN_ID)
}

/// Write `files` and the pinned binary path into `directory`, creating it.
/// The explicit install writes the way it always has: what the operator asked
/// for, over whatever is there.
fn write_files(directory: &Path, files: &[ShippedFile], bin_json: &str) -> Result<(), String> {
    std::fs::create_dir_all(directory)
        .map_err(|error| format!("creating {}: {error}", directory.display()))?;
    let bodies = files
        .iter()
        .map(|file| (file.name, file.body))
        .chain(std::iter::once(("bin.json", bin_json)));
    for (name, body) in bodies {
        let path = directory.join(name);
        std::fs::write(&path, body)
            .map_err(|error| format!("writing {}: {error}", path.display()))?;
    }
    Ok(())
}

/// `innerwarden observe install` - write the OpenClaw hook and the reply
/// plugin, and enable both.
///
/// The config is only rewritten when it parses as strict JSON, the same
/// discipline the MCP wiring follows: the file also holds the operator's auth
/// profiles and channel tokens, and a guard that mangles them has cost more
/// than it protects.
///
/// The plugin is granted conversation access, which OpenClaw requires before
/// it runs a non-bundled plugin's `agent_end` hook, and the output says so. An
/// entry the operator turned off stays off, and the operator's plugin policy
/// (`plugins.enabled`, `allow`, `deny`) is reported, never edited.
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
    let plugin_directory = plugin_dir(&home);
    let binary = std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "innerwarden".to_string());
    let bin_json = serde_json::json!({ "bin": binary }).to_string() + "\n";
    for (target, files) in [
        (&directory, &HOOK_FILES[..]),
        (&plugin_directory, &PLUGIN_FILES[..]),
    ] {
        if let Err(error) = write_files(target, files, &bin_json) {
            eprintln!("innerwarden observe: {error}");
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
             Enable the hook by hand: hooks.internal.entries.{HOOK_NAME}.enabled = true\n  \
             and the reply plugin: plugins.entries.{PLUGIN_ID}.enabled = true and\n  \
             plugins.entries.{PLUGIN_ID}.hooks.allowConversationAccess = true",
            config_path.display()
        );
        return std::process::ExitCode::from(1);
    };
    let (updated, hook_changed) = crate::observe::enable_hook_entry(root, HOOK_NAME);
    let (updated, plugin_entry) = enable_plugin_entry(updated, PLUGIN_ID);
    let changed = hook_changed || plugin_entry == PluginEntry::Enabled { changed: true };
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
         plugin: {}\n  \
         config: {}\n  \
         Restart the gateway to load them, then a dangerous ask is recorded even when\n  \
         the model refuses it. This is observation, not enforcement: each record\n  \
         names who decided, and a model refusal is never reported as a block.",
        directory.display(),
        plugin_directory.display(),
        config_path.display()
    );
    for line in plugin_install_lines(plugin_entry, plugin_blocker(&updated, PLUGIN_ID)) {
        println!("{line}");
    }
    std::process::ExitCode::SUCCESS
}

/// What `observe install` says about the reply plugin. PURE: how the entry
/// was left and what in the config still blocks it are handed in.
fn plugin_install_lines(entry: PluginEntry, blocker: Option<PluginBlocker>) -> Vec<String> {
    let not_seen = "  Until it runs, a Control UI ask is recorded after two minutes with the\n  \
                    outcome not seen.";
    let lines = match (entry, blocker) {
        (PluginEntry::UnexpectedShape, _) => format!(
            "  The reply plugin was not enabled: in the config,\n  \
             plugins.entries.{PLUGIN_ID} is not a table, so it was left as it is.\n\
             {not_seen}"
        ),
        (PluginEntry::LeftOff, _) => format!(
            "  The reply plugin is turned off in your config\n  \
             (plugins.entries.{PLUGIN_ID}), and an install does not turn back on\n  \
             what you turned off.\n\
             {not_seen}"
        ),
        (PluginEntry::Enabled { .. }, Some(blocker)) => format!(
            "  The reply plugin will not run:\n  \
             {}.\n  \
             That is your plugin policy, and it was left as it is.\n\
             {not_seen}",
            blocker.key(PLUGIN_ID)
        ),
        (PluginEntry::Enabled { .. }, None) => format!(
            "  The plugin reads how each Control UI turn ends (a tool call, a reply, or\n  \
             neither) so an ask made there is recorded with its outcome. OpenClaw lets a\n  \
             plugin read a turn only with conversation access, so it was granted:\n  \
             plugins.entries.{PLUGIN_ID}.hooks.allowConversationAccess\n  \
             No conversation text leaves the gateway through it. The gateway logs it as\n  \
             a plugin it cannot verify, because it was not installed through\n  \
             `openclaw plugins install`. To look at it:\n  \
             openclaw plugins inspect {PLUGIN_ID}"
        ),
    };
    lines.lines().map(str::to_string).collect()
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

/// The bytes found under each of `files` in `directory`, `None` for a file
/// that is not there, or the first error reading one. Read the way a config
/// the guard may rewrite is read: bounded, never through a link at the file's
/// name, and never blocking on something that is not a plain file. The
/// directory sits where the agent's own account can write, and the dashboard
/// reads it on every page.
fn read_installed(directory: &Path, files: &[ShippedFile]) -> Vec<Result<Option<Vec<u8>>, String>> {
    files
        .iter()
        .map(|file| {
            innerwarden_agent_guard::file_update::read_config_no_symlinks(
                directory,
                &directory.join(file.name),
            )
        })
        .collect()
}

/// Judge what `observe install` left in `directory` against what this version
/// ships. A file that is there and cannot be read as a plain file is not one
/// InnerWarden can vouch for, and is judged as changed.
fn judge(directory: &Path, files: &[ShippedFile]) -> InstalledFiles {
    let read = read_installed(directory, files);
    if matches!(read.first(), Some(Ok(None)) | None) {
        return InstalledFiles::NotInstalled;
    }
    let mut installed = Vec::with_capacity(read.len());
    for (file, bytes) in files.iter().zip(read) {
        match bytes {
            Ok(bytes) => installed.push(bytes),
            Err(_) => return InstalledFiles::Changed(file.name),
        }
    }
    installed_files(files, &installed)
}

/// What `observe install` left in OpenClaw on this host, as this version
/// judges it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Observation {
    /// The message hook's files.
    pub hook: InstalledFiles,
    /// The reply plugin's files.
    pub plugin: InstalledFiles,
    /// What in the OpenClaw config keeps the reply plugin from running. A
    /// config that cannot be read or parsed runs nothing: `EntryOff`.
    pub plugin_blocker: Option<PluginBlocker>,
}

impl Observation {
    /// Nothing installed, which is also what a host with no home reads as.
    pub(crate) const NONE: Self = Self {
        hook: InstalledFiles::NotInstalled,
        plugin: InstalledFiles::NotInstalled,
        plugin_blocker: None,
    };

    /// The reply plugin is there, is a version InnerWarden wrote, and nothing
    /// in the config keeps it from running.
    pub(crate) fn plugin_runs(&self) -> bool {
        matches!(
            self.plugin,
            InstalledFiles::Current | InstalledFiles::Outdated
        ) && self.plugin_blocker.is_none()
    }
}

/// [`Observation`] for this host.
pub(crate) fn observation() -> Observation {
    match innerwarden_agent_guard::hook::home_dir() {
        Ok(home) => observation_at(&home),
        Err(_) => Observation::NONE,
    }
}

fn observation_at(home: &Path) -> Observation {
    let config = std::fs::read_to_string(openclaw_config(home))
        .ok()
        .and_then(|body| serde_json::from_str::<Value>(&body).ok());
    Observation {
        hook: judge(&hook_dir(home), &HOOK_FILES),
        plugin: judge(&plugin_dir(home), &PLUGIN_FILES),
        plugin_blocker: match &config {
            Some(root) => plugin_blocker(root, PLUGIN_ID),
            None => Some(PluginBlocker::EntryOff),
        },
    }
}

/// Whether `observe install` left anything in OpenClaw on this host, for
/// `upgrade` to decide whether there is anything to refresh. Only names are
/// looked at.
pub(crate) fn openclaw_files_present() -> bool {
    let Ok(home) = innerwarden_agent_guard::hook::home_dir() else {
        return false;
    };
    [
        hook_dir(&home).join(HOOK_FILES[0].name),
        plugin_dir(&home).join(PLUGIN_FILES[0].name),
    ]
    .iter()
    .any(|path| std::fs::symlink_metadata(path).is_ok())
}

/// What `observe status` says about the files `observe install` wrote, after
/// its first lines. PURE.
fn observation_lines(observation: &Observation, prog: &str) -> Vec<String> {
    let mut lines = Vec::new();
    match observation.hook {
        InstalledFiles::Outdated => lines.push(format!(
            "  The installed hook is an earlier version's, and this version's records more.\n  \
             To update it:  {prog} observe install   (then restart the gateway)"
        )),
        InstalledFiles::Changed(file) => lines.push(format!(
            "  The installed hook is not the one InnerWarden wrote: {file} matches no\n  \
             version it shipped, so what it records cannot be relied on.\n  \
             To replace it:  {prog} observe install   (then restart the gateway)"
        )),
        InstalledFiles::NotInstalled | InstalledFiles::Current => {}
    }
    let not_seen = "an ask made there is recorded after two minutes with the\n  \
                    outcome not seen";
    match (observation.plugin, observation.plugin_blocker) {
        (InstalledFiles::NotInstalled, _) => lines.push(format!(
            "  Control UI chats: the reply plugin is not installed, so\n  \
             {not_seen}.\n  \
             To add it:  {prog} observe install   (then restart the gateway)"
        )),
        (InstalledFiles::Changed(file), _) => lines.push(format!(
            "  Control UI chats: the reply plugin is not the one InnerWarden wrote:\n  \
             {file} matches no version it shipped.\n  \
             To replace it:  {prog} observe install   (then restart the gateway)"
        )),
        (_, Some(blocker)) => lines.push(format!(
            "  Control UI chats: the reply plugin is installed but will not run:\n  \
             {}.\n  \
             Until it does, {not_seen}.",
            blocker.key(PLUGIN_ID)
        )),
        (InstalledFiles::Outdated, None) => lines.push(format!(
            "  Control UI chats: the reply plugin is an earlier version's.\n  \
             To update it:  {prog} observe install   (then restart the gateway)"
        )),
        (InstalledFiles::Current, None) => lines
            .push("  Control UI chats: the reply plugin reports how each turn ends.".to_string()),
    }
    lines
}

// ── refresh ──────────────────────────────────────────────────────────────────

/// What `observe refresh` did with one set of files.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Refreshed {
    NotInstalled,
    Current,
    Updated,
    /// Left as it is: this file is not one any release wrote.
    Changed(&'static str),
    /// Could not be read or replaced, for this reason.
    Failed(String),
}

/// Bring the files under `directory` up to this version's, if every one of
/// them is exactly what some release wrote.
///
/// Each file is replaced only if it still holds the bytes just read, and never
/// through a link anywhere below `home`: an upgrade can run as root while the
/// directory belongs to the account the gateway (and the agent) runs as, and
/// a link planted between the read and the write must not turn this into a
/// root write somewhere else. A file somebody changed is left alone, and so is
/// the rest of its set.
fn refresh_files(home: &Path, directory: &Path, files: &[ShippedFile]) -> Refreshed {
    let read = read_installed(directory, files);
    if matches!(read.first(), Some(Ok(None)) | None) {
        return Refreshed::NotInstalled;
    }
    let mut installed = Vec::with_capacity(read.len());
    for bytes in read {
        match bytes {
            Ok(bytes) => installed.push(bytes),
            Err(error) => return Refreshed::Failed(error),
        }
    }
    match installed_files(files, &installed) {
        InstalledFiles::NotInstalled => Refreshed::NotInstalled,
        InstalledFiles::Current => Refreshed::Current,
        InstalledFiles::Changed(file) => Refreshed::Changed(file),
        InstalledFiles::Outdated => {
            for (file, bytes) in files.iter().zip(&installed) {
                if bytes.as_deref() == Some(file.body.as_bytes()) {
                    continue;
                }
                if let Err(error) =
                    innerwarden_agent_guard::file_update::replace_if_unchanged_no_symlinks(
                        home,
                        &directory.join(file.name),
                        bytes.as_deref(),
                        file.body.as_bytes(),
                    )
                {
                    return Refreshed::Failed(error);
                }
            }
            Refreshed::Updated
        }
    }
}

/// What `observe refresh` prints. PURE. Nothing is said about a set that is
/// current or not installed, except that a hook without the reply plugin is
/// told what the plugin adds: an upgrade never installs what the operator
/// did not.
fn refresh_lines(hook: &Refreshed, plugin: &Refreshed, prog: &str) -> Vec<String> {
    let mut lines = Vec::new();
    for (what, refreshed) in [
        ("OpenClaw's message hook", hook),
        ("OpenClaw's reply plugin", plugin),
    ] {
        match refreshed {
            Refreshed::Updated => lines.push(format!("Updated {what} to this version's.")),
            Refreshed::Changed(file) => lines.push(format!(
                "{what} was left as it is: {file} matches no version InnerWarden shipped,\n\
                 so it was changed after it was installed. To replace it with this version's:\n  \
                 {prog} observe install"
            )),
            Refreshed::Failed(error) => lines.push(format!(
                "{what} could not be updated ({error}).\nTo update it:  {prog} observe install"
            )),
            Refreshed::NotInstalled | Refreshed::Current => {}
        }
    }
    if [hook, plugin].contains(&&Refreshed::Updated) {
        lines
            .push("Restart the OpenClaw gateway to load it: nothing here restarts it.".to_string());
    }
    let hook_in_place = matches!(hook, Refreshed::Current | Refreshed::Updated);
    if hook_in_place && *plugin == Refreshed::NotInstalled {
        lines.push(format!(
            "Control UI chats are recorded without how each turn ended. To add the reply\n\
             plugin that reads it (it is granted conversation access):  {prog} observe install"
        ));
    }
    lines
}

/// `innerwarden observe refresh` - bring the files `observe install` wrote up
/// to this version's, where they are exactly what an earlier release wrote.
///
/// `observe install` writes them once and replacing the binary does not touch
/// them, so `innerwarden upgrade` runs this with the NEW binary once it is in
/// place: only the new version knows what it ships. Nothing is installed that
/// was not, nothing anybody changed is overwritten (it is named instead), and
/// the gateway is never restarted. Exits 1 when a file could not be read or
/// replaced.
fn cmd_refresh(rest: &[String]) -> std::process::ExitCode {
    let home = match home(rest) {
        Ok(home) => home,
        Err(error) => {
            eprintln!("innerwarden observe: {error}");
            return std::process::ExitCode::from(2);
        }
    };
    let hook = refresh_files(&home, &hook_dir(&home), &HOOK_FILES);
    let plugin = refresh_files(&home, &plugin_dir(&home), &PLUGIN_FILES);
    for line in refresh_lines(&hook, &plugin, &crate::prog()) {
        println!("{line}");
    }
    if matches!(hook, Refreshed::Failed(_)) || matches!(plugin, Refreshed::Failed(_)) {
        return std::process::ExitCode::from(1);
    }
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
        for line in observation_lines(&observation_at(&home), &crate::prog()) {
            println!("{line}");
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
            message: String::new(),
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

    /// A pending state whose update lock somebody else holds costs ONE bounded
    /// wait, not one per attempt: the retry is for a lost compare-and-swap,
    /// and against a held lock it only waited again, four times over, in a
    /// call the OpenClaw hook kills at 4 s.
    ///
    /// FAILS ON REVERT: let `update_pending` retry a `LockBusy` like any
    /// other failure and the change is applied four times; take the lock with
    /// a blocking `flock` again and the update never returns.
    #[test]
    fn a_held_pending_lock_costs_one_wait_and_is_named() {
        use fs4::FileExt;
        use std::sync::mpsc;

        let dir = tempfile::TempDir::new().expect("scratch dir");
        let lock = dir.path().join(format!(".{PENDING_FILE}.innerwarden.lock"));
        let holder = innerwarden_agent_guard::file_update::open_shared_lock(&lock)
            .expect("open the pending state's update lock");
        FileExt::lock(&holder).expect("hold it, as any account that can open it may");

        let (done_tx, done_rx) = mpsc::channel();
        let scratch = dir.path().to_path_buf();
        std::thread::spawn(move || {
            let mut calls = 0;
            let updated = update_pending(&scratch, 1_000, |state| {
                calls += 1;
                state.remember(ask("agent:main:main", 1_000))
            });
            let _ = done_tx.send((updated.map(|_| ()), calls));
        });
        let (updated, calls) = done_rx
            .recv_timeout(std::time::Duration::from_secs(15))
            .expect("still waiting for a lock somebody else holds: the wait is not bounded");

        assert_eq!(calls, 1, "one attempt: a held lock is not retried");
        assert_eq!(
            updated,
            Err(ReplaceError::LockBusy {
                lock,
                waited: PENDING_LOCK_WAIT,
            }
            .to_string()),
            "refused for the held lock, and for nothing else"
        );
        assert!(
            !dir.path().join(PENDING_FILE).exists(),
            "nothing was written"
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

    /// The 1.5.1 message hook, as that release shipped it (read from the
    /// release tag). Every release from 1.2.0 to 1.5.1 shipped these bytes.
    const HANDLER_1_5_1: &str = include_str!("../tests/fixtures/openclaw-hook-1.5.1/handler.js");
    const HOOK_DOC_1_5_1: &str = include_str!("../tests/fixtures/openclaw-hook-1.5.1/HOOK.md");

    /// The digests of what THIS version ships, pinned. A release that changes
    /// one of these files must move the old digest into the file's `earlier`
    /// list, or every host still running the old file would read it as
    /// changed by somebody, and no upgrade would ever replace it. This fails
    /// until that is done, and checks the earlier digests against the real
    /// bytes 1.5.1 shipped rather than against a hex string alone.
    #[test]
    fn the_shipped_files_are_the_pinned_ones() {
        let pinned: [(&str, &str); 5] = [
            (
                "handler.js",
                "a1954a47b1dbf17124a9262606f170d0869db55803d2312f9571bb6d0d6b2b1b",
            ),
            (
                "HOOK.md",
                "391ab15bcede5c3e2297ce1abf007a4f0647176cd7b3a21426ba76327ca27987",
            ),
            (
                "index.js",
                "3dcec78c443d984105b34bbeda747bee3402ad8111528e8c2ebebdb35e85d2cd",
            ),
            (
                "openclaw.plugin.json",
                "19ba38f05331a870ed71289055e64e07309d20ebf4d5076068872ab9c9b53410",
            ),
            (
                "package.json",
                "7380542a44f9ba7596f69707d07d208f2f7221eaa850aa2f4291c50216aaa7f3",
            ),
        ];
        let shipped: Vec<&ShippedFile> = HOOK_FILES.iter().chain(PLUGIN_FILES.iter()).collect();
        for (file, (name, digest)) in shipped.iter().zip(pinned) {
            assert_eq!(file.name, name);
            assert_eq!(
                crate::observe::sha256_hex(file.body.as_bytes()),
                digest,
                "{name} changed: put the old digest in its `earlier` list, then pin the new one"
            );
            assert!(
                !file.earlier.contains(&digest),
                "{name}: current is not earlier"
            );
        }
        assert!(HOOK_FILES[0]
            .earlier
            .contains(&crate::observe::sha256_hex(HANDLER_1_5_1.as_bytes()).as_str()));
        assert!(HOOK_FILES[1]
            .earlier
            .contains(&crate::observe::sha256_hex(HOOK_DOC_1_5_1.as_bytes()).as_str()));
    }

    /// A home with the hook 1.5.1 installed (and its own bin.json).
    fn home_with_hook(handler: &str, doc: &str) -> tempfile::TempDir {
        let home = tempfile::TempDir::new().expect("home");
        let dir = hook_dir(home.path());
        std::fs::create_dir_all(&dir).expect("hook dir");
        std::fs::write(dir.join("handler.js"), handler).expect("handler");
        std::fs::write(dir.join("HOOK.md"), doc).expect("doc");
        std::fs::write(dir.join("bin.json"), "{\"bin\":\"/opt/iw/innerwarden\"}\n").expect("bin");
        home
    }

    /// The hook an earlier release wrote is replaced by this version's, file
    /// by file, and the host's own pinned binary path is left as it is.
    /// Nothing is installed that was not.
    ///
    /// FAILS ON REVERT: drop the write in `refresh_files` and the 1.5.1
    /// handler is still on disk after the refresh.
    #[test]
    fn a_hook_an_earlier_release_wrote_is_refreshed() {
        let home = home_with_hook(HANDLER_1_5_1, HOOK_DOC_1_5_1);
        let dir = hook_dir(home.path());
        assert_eq!(judge(&dir, &HOOK_FILES), InstalledFiles::Outdated);
        assert_eq!(
            refresh_files(home.path(), &dir, &HOOK_FILES),
            Refreshed::Updated
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("handler.js")).unwrap(),
            HOOK_HANDLER
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("HOOK.md")).unwrap(),
            HOOK_DOC
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("bin.json")).unwrap(),
            "{\"bin\":\"/opt/iw/innerwarden\"}\n"
        );
        assert_eq!(judge(&dir, &HOOK_FILES), InstalledFiles::Current);
        assert_eq!(
            refresh_files(home.path(), &dir, &HOOK_FILES),
            Refreshed::Current
        );
        // The plugin was never installed here, and a refresh does not add it.
        let plugin = plugin_dir(home.path());
        assert_eq!(
            refresh_files(home.path(), &plugin, &PLUGIN_FILES),
            Refreshed::NotInstalled
        );
        assert!(!plugin.exists());
    }

    /// A hook somebody changed is left exactly as it is, and named: it can be
    /// the operator's own fix, and it can be an agent's way of switching the
    /// observation off. Either way an upgrade must not erase it silently.
    ///
    /// FAILS ON REVERT: overwrite whatever is there and the edited handler is
    /// gone after the refresh.
    #[test]
    fn a_hook_somebody_changed_is_left_and_named() {
        let edited = format!("{HANDLER_1_5_1}\n// local change\n");
        let home = home_with_hook(&edited, HOOK_DOC_1_5_1);
        let dir = hook_dir(home.path());
        assert_eq!(
            refresh_files(home.path(), &dir, &HOOK_FILES),
            Refreshed::Changed("handler.js")
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("handler.js")).unwrap(),
            edited
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("HOOK.md")).unwrap(),
            HOOK_DOC_1_5_1,
            "the rest of the set is left too"
        );
        assert_eq!(
            judge(&dir, &HOOK_FILES),
            InstalledFiles::Changed("handler.js")
        );
    }

    /// An upgrade can run as root while the hook directory belongs to the
    /// account the gateway and the agent run as. A link planted at a hook
    /// file, pointing at a file holding the very bytes an earlier release
    /// wrote, must not turn the refresh into a root write through it.
    ///
    /// FAILS ON REVERT: read and replace with the link-following calls
    /// (`std::fs::read`, `replace`) and the victim holds this version's
    /// handler.
    #[cfg(unix)]
    #[test]
    fn a_link_at_a_hook_file_is_never_refreshed_through() {
        let home = home_with_hook(HANDLER_1_5_1, HOOK_DOC_1_5_1);
        let dir = hook_dir(home.path());
        let victim = home.path().join("victim.js");
        std::fs::write(&victim, HANDLER_1_5_1).expect("victim");
        std::fs::remove_file(dir.join("handler.js")).expect("unlink");
        std::os::unix::fs::symlink(&victim, dir.join("handler.js")).expect("plant link");

        let refreshed = refresh_files(home.path(), &dir, &HOOK_FILES);
        assert!(matches!(refreshed, Refreshed::Failed(_)), "{refreshed:?}");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), HANDLER_1_5_1);
        assert!(std::fs::symlink_metadata(dir.join("handler.js"))
            .unwrap()
            .file_type()
            .is_symlink());
        // Status and the dashboard read it as not the file InnerWarden wrote.
        assert_eq!(
            judge(&dir, &HOOK_FILES),
            InstalledFiles::Changed("handler.js")
        );
    }

    /// What the refresh says, and what it never says: nothing for a set that
    /// is current or absent, the restart step only when it wrote something,
    /// and the plugin offered (never installed) where only the hook is there.
    #[test]
    fn the_refresh_says_what_it_did_and_what_is_left() {
        let lines = |hook: Refreshed, plugin: Refreshed| {
            refresh_lines(&hook, &plugin, "innerwarden").join("\n")
        };
        assert_eq!(lines(Refreshed::NotInstalled, Refreshed::NotInstalled), "");
        assert_eq!(lines(Refreshed::Current, Refreshed::Current), "");
        let updated = lines(Refreshed::Updated, Refreshed::Current);
        assert!(
            updated.contains("Updated OpenClaw's message hook"),
            "{updated}"
        );
        assert!(
            updated.contains("Restart the OpenClaw gateway"),
            "{updated}"
        );
        let changed = lines(Refreshed::Changed("handler.js"), Refreshed::Current);
        assert!(
            changed.contains("left as it is: handler.js matches no version"),
            "{changed}"
        );
        assert!(changed.contains("innerwarden observe install"), "{changed}");
        assert!(
            !changed.contains("Restart"),
            "nothing was written: {changed}"
        );
        let failed = lines(
            Refreshed::Failed("refused a link".into()),
            Refreshed::Current,
        );
        assert!(
            failed.contains("could not be updated (refused a link)"),
            "{failed}"
        );
        let no_plugin = lines(Refreshed::Updated, Refreshed::NotInstalled);
        assert!(no_plugin.contains("To add the reply"), "{no_plugin}");
        assert!(no_plugin.contains("conversation access"), "{no_plugin}");
        assert!(!lines(Refreshed::NotInstalled, Refreshed::NotInstalled).contains("reply"));
    }

    /// The install says what it granted the plugin, and when the operator's
    /// own settings keep it from running, which setting, and that it was left.
    #[test]
    fn the_install_says_what_the_plugin_was_granted_or_why_it_will_not_run() {
        let granted = plugin_install_lines(PluginEntry::Enabled { changed: true }, None).join("\n");
        assert!(granted.contains("allowConversationAccess"), "{granted}");
        assert!(granted.contains("No conversation"), "{granted}");
        let blocked = plugin_install_lines(
            PluginEntry::Enabled { changed: true },
            Some(PluginBlocker::NotInAllowList),
        )
        .join("\n");
        assert!(
            blocked.contains("will not run:\n  plugins.allow does not list innerwarden-replies"),
            "{blocked}"
        );
        assert!(blocked.contains("outcome not seen"), "{blocked}");
        let off =
            plugin_install_lines(PluginEntry::LeftOff, Some(PluginBlocker::EntryOff)).join("\n");
        assert!(off.contains("does not turn back on"), "{off}");
        let odd = plugin_install_lines(PluginEntry::UnexpectedShape, None).join("\n");
        assert!(odd.contains("not a table"), "{odd}");
        for lines in [granted, blocked, off, odd] {
            for line in lines.lines() {
                assert!(line.chars().count() <= 80, "wrap this line: {line}");
            }
        }
    }

    /// `observe status` names the state of each set, and a plugin the config
    /// blocks names the setting.
    #[test]
    fn status_names_an_earlier_or_changed_hook_and_the_plugin_state() {
        let lines = |hook, plugin, blocker| {
            observation_lines(
                &Observation {
                    hook,
                    plugin,
                    plugin_blocker: blocker,
                },
                "innerwarden",
            )
            .join("\n")
        };
        let all_good = lines(InstalledFiles::Current, InstalledFiles::Current, None);
        assert_eq!(
            all_good,
            "  Control UI chats: the reply plugin reports how each turn ends."
        );
        let stale = lines(InstalledFiles::Outdated, InstalledFiles::Current, None);
        assert!(stale.contains("an earlier version's"), "{stale}");
        let changed = lines(
            InstalledFiles::Changed("handler.js"),
            InstalledFiles::Current,
            None,
        );
        assert!(
            changed.contains("not the one InnerWarden wrote: handler.js"),
            "{changed}"
        );
        let missing = lines(InstalledFiles::Current, InstalledFiles::NotInstalled, None);
        assert!(
            missing.contains("reply plugin is not installed"),
            "{missing}"
        );
        let blocked = lines(
            InstalledFiles::Current,
            InstalledFiles::Current,
            Some(PluginBlocker::AllPluginsOff),
        );
        assert!(
            blocked.contains("will not run:\n  plugins.enabled is false"),
            "{blocked}"
        );
        for text in [all_good, stale, changed, missing, blocked] {
            for line in text.lines() {
                assert!(line.chars().count() <= 82, "wrap this line: {line}");
            }
        }
    }

    /// A turn's end closes the ask it started, recorded once, and with how
    /// the turn ended as its basis.
    #[test]
    fn a_turn_end_records_its_ask_once_with_how_it_ended() {
        let dir = tempfile::TempDir::new().expect("scratch dir");
        update_pending(dir.path(), 1_000, |state| {
            state.remember(PendingAsk {
                message: "run-1".into(),
                ..ask("agent:main:main", 1_000)
            })
        })
        .expect("held");
        let end = |run: &str| {
            settle_with(dir.path(), 1_010, |state| {
                state
                    .take_for_run("agent:main:main", run)
                    .map(|ask| Leaving {
                        ask,
                        departure: Departure::TurnEnded(TurnEnd::UsedTools),
                    })
                    .into_iter()
                    .collect()
            })
        };
        end("run-0");
        assert!(
            attempts(dir.path()).is_empty(),
            "another turn closes nothing"
        );
        end("run-1");
        end("run-1");
        let recorded = attempts(dir.path());
        assert_eq!(recorded.len(), 1, "{recorded:?}");
        assert_eq!(recorded[0]["decider"], "undetermined");
        assert_eq!(recorded[0]["decider_basis"], "tool_call_in_turn");
        assert_eq!(recorded[0]["enforced"], false);
    }
}
