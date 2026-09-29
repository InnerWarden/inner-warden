//! The Community dashboard's own answers: the three lanes on the Overview, the
//! flagged decisions the Cases screen lists, the guard's event log, and what
//! Community covers on this machine.
//!
//! Every function here is PURE: it takes what `dashboard.rs` read (the graph,
//! the event log's text, a few facts about local configuration, the time) and
//! returns the JSON a route serves. The sentences about the record are written
//! here, from the same facts they count, and the page prints them as sent:
//! the page owns labels and the product's names, never a sentence about what
//! happened and never a command built from parts.
//!
//! What this module must never send (and its tests pin): a suppression
//! pattern, a key, a full path for a project, a raw MCP argument beyond the
//! redacted summary the record already holds, or anything from another
//! product's files.

use innerwarden_graph::{
    DecisionBrief, DecisionCursor, DecisionDetail, DecisionRecord, DecisionsPage, RecordSpan,
    SessionFacts, Tally, TALLY_KEYS,
};
use serde_json::{json, Map, Value};

use crate::concern;
use crate::suppress::{glob_match, SuppressConfig};

pub(crate) const SCHEMA_VERSION: u32 = 1;
const DAY_MS: u64 = 86_400_000;
/// The span the agent's and the messages' lane cards count.
pub(crate) const LANE_WINDOW_MS: u64 = 7 * DAY_MS;
/// The event log's refusals, week by week, at most this many weeks back.
const MAX_WEEKS: u64 = 26;
/// A message's text is cut to this many characters before it is served.
const MESSAGE_DETAIL_MAX: usize = 240;
/// A lane card's newest item names at most this much of its command.
const LATEST_COMMAND_MAX: usize = 80;
const LANE_SENTENCE_MAX: usize = 600;
/// The marker `redact_secrets` writes in place of a secret.
const REDACTION_MARKER: &str = "[REDACTED]";

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

/// RFC 3339 in UTC, to the second, from Unix milliseconds. Pure (no clock, no
/// time zone database): the civil-from-days algorithm.
pub(crate) fn rfc3339(ms: u64) -> String {
    let secs = ms / 1_000;
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60
    )
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The Monday (UTC) of the week holding `ms`, as `YYYY-MM-DD`, and its day
/// number since the epoch.
fn week_start(ms: u64) -> (u64, String) {
    let days = ms / DAY_MS;
    // 1970-01-01 was a Thursday: (days + 3) % 7 is 0 on a Monday.
    let monday = days - (days + 3) % 7;
    let (year, month, day) = civil_from_days(monday as i64);
    (monday, format!("{year:04}-{month:02}-{day:02}"))
}

fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{} {}", group(count), if count == 1 { one } else { many })
}

/// A count with thousands separators, the way the page prints it.
fn group(count: usize) -> String {
    let digits = count.to_string();
    let mut out = String::new();
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// One line, at most `max` characters, with an ellipsis when cut.
fn one_line(text: &str, max: usize) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        return flat;
    }
    let head: String = flat.chars().take(max.saturating_sub(1)).collect();
    format!("{}…", head.trim_end())
}

/// An agent id in the words a person reads ("claude-code" is "Claude Code").
pub(crate) fn agent_name(id: &str) -> String {
    match id {
        "claude-code" | "claude" => "Claude Code".into(),
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

fn opt<T: serde::Serialize>(object: &mut Map<String, Value>, key: &str, value: Option<T>) {
    if let Some(value) = value {
        object.insert(key.into(), json!(value));
    }
}

// ---------------------------------------------------------------------------
// The record
// ---------------------------------------------------------------------------

/// `record`: how much the decision record holds and how far back it goes.
pub(crate) fn record_json(span: &RecordSpan) -> Value {
    let mut object = Map::new();
    object.insert("decisions".into(), json!(span.decisions));
    object.insert("flagged".into(), json!(span.flagged));
    opt(&mut object, "oldest_at", span.oldest_at_ms.map(rfc3339));
    opt(&mut object, "newest_at", span.newest_at_ms.map(rfc3339));
    Value::Object(object)
}

// ---------------------------------------------------------------------------
// The event log
// ---------------------------------------------------------------------------

/// One message someone sent the agent, as `innerwarden observe` recorded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Attempt {
    pub id: String,
    pub ts: u64,
    pub channel: String,
    pub sender: Option<String>,
    pub surface: String,
    pub decider: String,
    pub enforced: bool,
    pub recommendation: String,
    pub risk: Option<u64>,
    pub detail: String,
}

/// What the guard's append-only event log holds, counted once per read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct EventLog {
    /// False when the file exists and could not be read.
    pub readable: bool,
    pub unparsable_lines: usize,
    pub earliest_ts: Option<u64>,
    /// Seconds since the epoch of each refusal the guard made.
    pub blocked: Vec<u64>,
    /// Seconds since the epoch of each refusal monitor mode recorded instead.
    pub would_block: Vec<u64>,
    /// Newest first.
    pub attempts: Vec<Attempt>,
    pub suppression_changes: usize,
}

impl EventLog {
    pub(crate) fn unreadable() -> Self {
        Self {
            readable: false,
            ..Self::default()
        }
    }
}

/// A short, stable id for one log line: equal lines, equal ids.
fn line_id(line: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(line.as_bytes());
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse the log's text. A line that is not a JSON object is counted, never
/// fatal: one torn write must not blank the history above it.
pub(crate) fn parse_event_log(text: &str) -> EventLog {
    let mut log = EventLog {
        readable: true,
        ..EventLog::default()
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(Value::Object(record)) = serde_json::from_str::<Value>(line) else {
            log.unparsable_lines += 1;
            continue;
        };
        let text = |key: &str| {
            record
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        let Some(ts) = record.get("ts").and_then(Value::as_u64) else {
            log.unparsable_lines += 1;
            continue;
        };
        log.earliest_ts = Some(log.earliest_ts.map_or(ts, |earliest| earliest.min(ts)));
        match record.get("kind").and_then(Value::as_str) {
            Some("guard.blocked") => match record.get("outcome").and_then(Value::as_str) {
                Some("blocked") => log.blocked.push(ts),
                Some("would_block") => log.would_block.push(ts),
                _ => {}
            },
            Some("guard.suppression_changed") => log.suppression_changes += 1,
            Some("guard.attempt") => {
                let detail = innerwarden_agent_guard::redact::redact_secrets(&text("detail")).text;
                log.attempts.push(Attempt {
                    id: line_id(line),
                    ts,
                    channel: text("channel"),
                    sender: record
                        .get("sender")
                        .and_then(Value::as_str)
                        .filter(|sender| !sender.trim().is_empty())
                        .map(|sender| one_line(sender, 64)),
                    surface: text("surface"),
                    decider: text("decider"),
                    enforced: record
                        .get("enforced")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    recommendation: text("recommendation"),
                    risk: record.get("risk_score").and_then(Value::as_u64),
                    detail: one_line(&detail, MESSAGE_DETAIL_MAX),
                });
            }
            _ => {}
        }
    }
    log.attempts
        .sort_by(|a, b| b.ts.cmp(&a.ts).then_with(|| b.id.cmp(&a.id)));
    log
}

/// A message's outcome key, from who decided. A model that declined is the
/// agent's own doing; only a control that refused is InnerWarden's.
fn attempt_outcome(attempt: &Attempt) -> &'static str {
    match attempt.decider.as_str() {
        "model_refused" => "declined_by_agent",
        "guard_denied" | "kernel_denied" if attempt.enforced => "stopped_by_innerwarden",
        _ => "unplaced",
    }
}

fn channel_words(channel: &str) -> String {
    match channel {
        "telegram" => "Telegram".into(),
        "slack" => "Slack".into(),
        "discord" => "Discord".into(),
        "whatsapp" => "WhatsApp".into(),
        "signal" => "Signal".into(),
        "" => "a chat".into(),
        other => agent_name(other),
    }
}

fn decider_words(decider: &str) -> &'static str {
    match decider {
        "model_refused" => "Your agent declined on its own",
        "guard_denied" => "The guard refused it",
        "kernel_denied" => "The kernel refused it",
        _ => "Who decided was not recorded",
    }
}

/// `GET /api/guard/history`: the event log, counted.
pub(crate) fn history_json(log: &EventLog, now_ms: u64) -> Value {
    let mut weeks: Vec<Value> = Vec::new();
    if let Some(earliest) = log.earliest_ts {
        let (now_monday, _) = week_start(now_ms);
        let (first_monday, _) = week_start(earliest.saturating_mul(1_000));
        let from = first_monday.max(now_monday.saturating_sub((MAX_WEEKS - 1) * 7));
        let mut monday = from;
        while monday <= now_monday {
            let start_ms = monday * DAY_MS;
            let end_ms = start_ms + 7 * DAY_MS;
            let within = |ts: &u64| {
                let ms = ts.saturating_mul(1_000);
                ms >= start_ms && ms < end_ms
            };
            let (_, label) = week_start(start_ms);
            weeks.push(json!({
                "start": label,
                "blocked": log.blocked.iter().filter(|ts| within(ts)).count(),
                "would_block": log.would_block.iter().filter(|ts| within(ts)).count(),
            }));
            monday += 7;
        }
    }
    let window_start = now_ms.saturating_sub(LANE_WINDOW_MS) / 1_000;
    let mut messages = Map::new();
    messages.insert("recorded".into(), json!(log.attempts.len()));
    messages.insert(
        "last_7d".into(),
        json!(log
            .attempts
            .iter()
            .filter(|attempt| attempt.ts >= window_start)
            .count()),
    );
    if let Some(latest) = log.attempts.first() {
        messages.insert(
            "latest".into(),
            json!({ "at": rfc3339(latest.ts * 1_000), "detail": latest.detail }),
        );
    }
    let mut object = Map::new();
    object.insert("schema_version".into(), json!(SCHEMA_VERSION));
    object.insert("generated_at_ms".into(), json!(now_ms));
    object.insert("readable".into(), json!(log.readable));
    opt(
        &mut object,
        "since",
        log.earliest_ts.map(|ts| rfc3339(ts * 1_000)),
    );
    object.insert("unparsable_lines".into(), json!(log.unparsable_lines));
    object.insert(
        "refusals".into(),
        json!({
            "blocked": log.blocked.len(),
            "would_block": log.would_block.len(),
            "weeks": weeks,
        }),
    );
    object.insert("messages".into(), Value::Object(messages));
    object.insert("suppression_changes".into(), json!(log.suppression_changes));
    Value::Object(object)
}

fn attempt_json(attempt: &Attempt) -> Value {
    let mut object = Map::new();
    object.insert("id".into(), json!(attempt.id));
    object.insert("at".into(), json!(rfc3339(attempt.ts * 1_000)));
    object.insert("channel".into(), json!(attempt.channel));
    object.insert(
        "channel_words".into(),
        json!(channel_words(&attempt.channel)),
    );
    opt(&mut object, "sender", attempt.sender.clone());
    object.insert("surface".into(), json!(attempt.surface));
    object.insert("decider".into(), json!(decider_words(&attempt.decider)));
    object.insert("decider_key".into(), json!(attempt.decider));
    object.insert("enforced".into(), json!(attempt.enforced));
    object.insert("recommendation".into(), json!(attempt.recommendation));
    opt(&mut object, "risk", attempt.risk);
    object.insert("detail".into(), json!(attempt.detail));
    object.insert("outcome_key".into(), json!(attempt_outcome(attempt)));
    Value::Object(object)
}

/// `GET /api/guard/history?kind=attempt`: one page of messages, newest first.
/// The cursor is the id of the last item served; an unknown one starts from
/// the top rather than repeat or skip anything silently (the ids are stable
/// per line, and the log only grows at its end).
pub(crate) fn attempts_json(log: &EventLog, cursor: Option<&str>, limit: usize) -> Value {
    let limit = limit.clamp(1, 50);
    let start = cursor
        .and_then(|cursor| log.attempts.iter().position(|attempt| attempt.id == cursor))
        .map_or(0, |at| at + 1);
    let page: Vec<&Attempt> = log.attempts.iter().skip(start).take(limit + 1).collect();
    let more = page.len() > limit;
    let items: Vec<Value> = page.iter().take(limit).map(|a| attempt_json(a)).collect();
    let mut object = Map::new();
    object.insert("schema_version".into(), json!(SCHEMA_VERSION));
    object.insert("items".into(), json!(items));
    object.insert("total".into(), json!(log.attempts.len()));
    if more {
        opt(
            &mut object,
            "next_cursor",
            page.get(limit - 1).map(|a| a.id.clone()),
        );
    }
    Value::Object(object)
}

// ---------------------------------------------------------------------------
// Lanes
// ---------------------------------------------------------------------------

/// What the Overview's three cards are built from.
pub(crate) struct LaneFacts<'a> {
    pub now_ms: u64,
    pub tally: &'a Tally,
    pub record: &'a RecordSpan,
    /// The host-wide guard mode (`guard/meta`), `not_configured` when no agent
    /// has the guard in front of it.
    pub guard_mode: &'a str,
    pub observe_installed: bool,
    pub log: &'a EventLog,
}

fn part_label(key: &str, count: usize) -> &'static str {
    let one = count == 1;
    match key {
        "refused_before_run" => {
            if one {
                "refused before it ran"
            } else {
                "refused before they ran"
            }
        }
        "unsafe_may_have_run" => {
            if one {
                "judged unsafe, and it ran"
            } else {
                "judged unsafe, and they ran"
            }
        }
        "would_have_refused" => "would have been refused (monitor mode)",
        "flagged_ran" => {
            if one {
                "flagged, and it ran"
            } else {
                "flagged, and they ran"
            }
        }
        "allowed" => "allowed",
        "stopped_by_innerwarden" => "stopped by InnerWarden",
        "declined_by_agent" => "your agent declined",
        _ => "outcome not recorded",
    }
}

fn agent_actions_lane(facts: &LaneFacts<'_>) -> Value {
    let connected = matches!(
        facts.guard_mode,
        "monitor" | "enforce" | "mixed" | "partial"
    );
    if facts.guard_mode == "not_configured" && facts.record.decisions == 0 {
        return json!({
            "lane": "agent_actions",
            "availability": "no_source",
            "sentence": "No agent is connected to the guard yet.",
            "next_step": {
                "command": "innerwarden agents connect --all --monitor",
                "line": "Connects every agent it finds, in monitor mode: it records and refuses nothing.",
            },
        });
    }
    let tally = facts.tally;
    let window_start = facts.now_ms.saturating_sub(LANE_WINDOW_MS);
    let mut object = Map::new();
    object.insert("lane".into(), json!("agent_actions"));
    object.insert("availability".into(), json!("available"));
    object.insert("count_of".into(), json!("commands"));
    object.insert("window".into(), json!("7d"));
    object.insert("count".into(), json!(tally.count));
    // The record starts inside the window: the card says "since" that day
    // rather than claim seven days it does not hold.
    if let Some(oldest) = facts
        .record
        .oldest_at_ms
        .filter(|oldest| *oldest > window_start)
    {
        object.insert("since".into(), json!(rfc3339(oldest)));
    }
    let sentence = if tally.count == 0 {
        if facts.record.decisions == 0 {
            if connected {
                "Connected. Nothing screened yet.".to_string()
            } else {
                "Nothing screened yet.".to_string()
            }
        } else {
            "Nothing your agents tried was recorded in the last 7 days.".to_string()
        }
    } else {
        let refused = tally.parts.get("refused_before_run").copied().unwrap_or(0);
        let mut sentence = format!(
            "Your agents tried {} in this span, and the guard flagged {}.",
            plural(tally.count, "command", "commands"),
            group(tally.flagged)
        );
        if tally.all_monitor {
            sentence.push_str(
                " Every decision was made in monitor mode, which records and refuses nothing.",
            );
        } else if refused > 0 {
            sentence.push_str(&format!(
                " It refused {} before {} ran.",
                group(refused),
                if refused == 1 { "it" } else { "they" }
            ));
        }
        sentence
    };
    object.insert(
        "sentence".into(),
        json!(one_line(&sentence, LANE_SENTENCE_MAX)),
    );
    let breakdown: Vec<Value> = TALLY_KEYS
        .iter()
        .filter_map(|key| {
            let count = tally.parts.get(key).copied().unwrap_or(0);
            (count > 0)
                .then(|| json!({ "key": key, "count": count, "label": part_label(key, count) }))
        })
        .collect();
    if tally.count > 0 {
        object.insert("breakdown".into(), json!(breakdown));
    }
    if let Some(latest) = &tally.latest_flagged {
        if let Some(at) = latest.recorded_at_ms {
            object.insert(
                "latest".into(),
                json!({
                    "title": format!("{} tried {}", who(latest), one_line(&latest.command, LATEST_COMMAND_MAX)),
                    "at": rfc3339(at),
                    "case_id": latest.id,
                }),
            );
        }
    }
    Value::Object(object)
}

fn agent_messages_lane(facts: &LaneFacts<'_>) -> Value {
    let log = facts.log;
    if !facts.observe_installed && log.attempts.is_empty() {
        return json!({
            "lane": "agent_messages",
            "availability": "no_source",
            "sentence": "Nothing records what people ask your agent yet.",
            "next_step": {
                "command": "innerwarden observe install",
                "line": "Records the risky messages people send your agent. It does not block them.",
            },
        });
    }
    let window_start = facts.now_ms.saturating_sub(LANE_WINDOW_MS) / 1_000;
    let recent: Vec<&Attempt> = log
        .attempts
        .iter()
        .filter(|attempt| attempt.ts >= window_start)
        .collect();
    let mut parts: Vec<(&'static str, usize)> = Vec::new();
    for key in ["stopped_by_innerwarden", "declined_by_agent", "unplaced"] {
        let count = recent
            .iter()
            .filter(|attempt| attempt_outcome(attempt) == key)
            .count();
        if count > 0 {
            parts.push((key, count));
        }
    }
    let mut object = Map::new();
    object.insert("lane".into(), json!("agent_messages"));
    object.insert("availability".into(), json!("available"));
    object.insert("count_of".into(), json!("messages"));
    object.insert("window".into(), json!("7d"));
    object.insert("count".into(), json!(recent.len()));
    let sentence = if recent.is_empty() {
        "Nothing risky reached your agent in conversation in the last 7 days.".to_string()
    } else {
        format!(
            "{} reached your agent in the last 7 days. Observe records them; it does not block them.",
            plural(recent.len(), "risky message", "risky messages")
        )
    };
    object.insert("sentence".into(), json!(sentence));
    if !recent.is_empty() {
        object.insert(
            "breakdown".into(),
            json!(parts
                .iter()
                .map(|(key, count)| json!({ "key": key, "count": count, "label": part_label(key, *count) }))
                .collect::<Vec<_>>()),
        );
    }
    if let Some(latest) = log.attempts.first() {
        object.insert(
            "latest".into(),
            json!({
                "title": format!(
                    "Someone on {} asked your agent: {}",
                    channel_words(&latest.channel),
                    one_line(&latest.detail, LATEST_COMMAND_MAX)
                ),
                "at": rfc3339(latest.ts * 1_000),
                "case_id": latest.id,
            }),
        );
    }
    Value::Object(object)
}

/// `lanes`: the three cards. The server's lane is always `no_source` here:
/// Community watches what agents try to run, never the machine itself.
pub(crate) fn lanes_json(facts: &LaneFacts<'_>) -> Value {
    json!({
        "agent_messages": agent_messages_lane(facts),
        "agent_actions": agent_actions_lane(facts),
        "server_attacks": {
            "lane": "server_attacks",
            "availability": "no_source",
            "sentence": "Community watches what your AI agents try to run. It does not watch this machine itself.",
        },
    })
}

/// `GET /api/guard/overview`: the graph's own overview, unchanged, plus the
/// lanes and the record. The graph's struct is not touched: the paid agent
/// serves it too and adds its own fields beside it.
pub(crate) fn overview_json(mut overview: Value, facts: &LaneFacts<'_>) -> Value {
    if let Some(object) = overview.as_object_mut() {
        object.insert("lanes".into(), lanes_json(facts));
        object.insert("record".into(), record_json(facts.record));
    }
    overview
}

// ---------------------------------------------------------------------------
// Decisions
// ---------------------------------------------------------------------------

/// Who asked, in words. Only an agent the record NAMES is named.
fn who(record: &DecisionRecord) -> String {
    if let Some(agent) = &record.agent {
        return agent_name(agent);
    }
    match record.channel {
        "check" => "You".into(),
        "mcp" => "An MCP connection".into(),
        "hook" => "An agent".into(),
        _ => "An agent".into(),
    }
}

fn text(text: impl Into<String>) -> Value {
    json!({ "kind": "text", "text": text.into() })
}

fn code(text: impl Into<String>) -> Value {
    json!({ "kind": "code", "text": text.into() })
}

fn time(ms: u64) -> Value {
    json!({ "kind": "time", "at": rfc3339(ms) })
}

/// What happened, as segments the page prints in order: text as text, a
/// folder or a command as code, a time through the page's own clock.
fn happened(record: &DecisionRecord) -> Vec<Value> {
    let mut segments = Vec::new();
    let named = record.agent.as_deref().map(agent_name);
    let opening = match (record.channel, named) {
        ("check", _) => "You checked this command by hand".to_string(),
        ("mcp", Some(agent)) => format!("{agent} asked to call this tool"),
        ("mcp", None) => "An agent asked, through an MCP connection, to call this tool".into(),
        ("hook", Some(agent)) => format!("{agent} asked to run this"),
        ("hook", None) => "An agent asked, through its shell hook, to run this".into(),
        (_, Some(agent)) => format!("{agent} asked to run this"),
        (_, None) => "An agent asked to run this".into(),
    };
    segments.push(text(opening));
    if let Some(project) = &record.project {
        segments.push(text(" in the folder "));
        segments.push(code(project.clone()));
    }
    if let Some(ms) = record.recorded_at_ms {
        segments.push(text(" on "));
        segments.push(time(ms));
    }
    if record.flagged {
        if record.reason_words.is_empty() {
            segments.push(text(". The guard flagged it."));
        } else {
            let more = match record.reasons_more {
                0 => String::new(),
                n => format!(", and {}", plural(n, "more reason", "more reasons")),
            };
            segments.push(text(format!(
                ". The guard flagged it: {}{more}.",
                record.reason_words.trim_end_matches('.')
            )));
        }
    } else {
        segments.push(text(". The guard allowed it."));
    }
    segments
}

/// What InnerWarden did, in one sentence, by verdict, outcome and mode.
fn did(record: &DecisionRecord) -> String {
    let rules_said = match record.recommendation.as_str() {
        "deny" => "The rules said deny",
        "review" => "The rules asked for a review",
        "allow" => "The rules allowed it",
        _ => "The rules gave no verdict",
    };
    match (
        record.outcome.as_str(),
        record.recommendation.as_str(),
        record.mode_at_decision.as_str(),
    ) {
        (_, _, "check") | ("screened", _, _) => {
            "You checked this by hand with innerwarden check. Nothing ran.".into()
        }
        ("blocked", "review", _) => {
            "The rules asked for a review, and the guard refused it before it ran, as set up."
                .into()
        }
        ("blocked", _, _) => format!("{rules_said}, and the guard refused it before it ran."),
        ("would_block", _, _) => {
            format!("{rules_said}. Monitor mode records and does not refuse, so it ran.")
        }
        ("allowed", "deny", "monitor") if record.channel == "mcp" => {
            "The rules said deny. This MCP connection only warns, so the call went through.".into()
        }
        ("allowed", "deny", "monitor") => {
            "The rules said deny. Monitor mode records and does not refuse, so it ran.".into()
        }
        ("allowed", "deny", _) => {
            "The rules said deny, but this call carried no request the guard could refuse, so it went through."
                .into()
        }
        ("allowed", "review", "monitor") => {
            "The rules asked for a review. Monitor mode records and does not refuse, so it ran."
                .into()
        }
        ("allowed", "review", _) => {
            "The rules asked for a review. Only a deny is refused, so it ran.".into()
        }
        ("allowed", "allow", _) => "The rules allowed it, so it ran.".into(),
        _ => match record.recommendation.as_str() {
            "deny" | "review" | "allow" => {
                format!("{rules_said}. What happened next was not recorded.")
            }
            _ => "What happened to it was not recorded.".into(),
        },
    }
}

/// Whether the stored command is the whole command, as it ran.
fn command_whole(record: &DecisionRecord) -> bool {
    !record.command_shortened && !record.command.contains(REDACTION_MARKER)
}

/// Quote a command for a POSIX shell: single quotes, with a quote inside
/// written as `'\''`. The same form the hook prints for `innerwarden allow`.
fn shell_quote(command: &str) -> String {
    format!("'{}'", command.replace('\'', "'\\''"))
}

fn step(label: &str, command: Option<String>, line: &str) -> Value {
    let mut object = Map::new();
    object.insert("label".into(), json!(label));
    opt(&mut object, "command", command);
    object.insert("line".into(), json!(line));
    Value::Object(object)
}

/// The ATR rule a single `innerwarden mute` would quiet, when the decision's
/// every reason is that one rule. A base signal can never be muted
/// (`suppress::apply`), and a decision with two rules needs both muted, which
/// is not one step.
fn single_mutable_rule(record: &DecisionRecord) -> Option<&str> {
    match record.rules.as_slice() {
        [only] if concern::is_mutable_rule(only) => Some(only.as_str()),
        _ => None,
    }
}

/// What the person can do, at most two steps, most useful first.
///
/// The security lens, pinned by tests: an allow or a mute is never offered for
/// a deny, never offered as the first step of a refusal the guard could make,
/// and an allow pattern is never generated from a command the record
/// shortened or redacted (it would widen, or match nothing).
fn next_steps(record: &DecisionRecord, suppress: &SuppressConfig) -> Vec<Value> {
    let enforce = || {
        step(
            "Refuse it next time:",
            Some("innerwarden enforce".into()),
            "A deny is then refused before it runs, for every connected agent.",
        )
    };
    let whole = command_whole(record);
    if whole
        && suppress
            .allow
            .iter()
            .any(|pattern| glob_match(pattern, &record.command))
    {
        return vec![step(
            "Nothing to do.",
            None,
            "You have since allowed commands like this one.",
        )];
    }
    match record.outcome_key {
        "refused_before_run" => {
            vec![step(
                "Nothing to do.",
                None,
                "The guard refused it before it ran.",
            )]
        }
        "checked_only" => vec![step("Nothing to do.", None, "A check runs nothing.")],
        "unplaced" => vec![step(
            "Nothing to do here.",
            None,
            "This record is older than the field that says what happened next.",
        )],
        "allowed" => Vec::new(),
        _ if record.recommendation == "deny" => {
            if record.mode_at_decision == "enforce" {
                vec![step(
                    "Nothing more to do here.",
                    None,
                    "The guard was already refusing; this call gave it nothing to refuse.",
                )]
            } else {
                vec![enforce()]
            }
        }
        _ => {
            let mut steps = Vec::new();
            if record.outcome_key == "would_have_refused" {
                steps.push(enforce());
            }
            if record.recommendation == "review" {
                if let Some(rule) = single_mutable_rule(record) {
                    steps.push(step(
                        "If this is routine for you:",
                        Some(format!("innerwarden mute {rule}")),
                        "The guard stops flagging this rule. Other rules still apply.",
                    ));
                } else if whole
                    && !record.command.contains('*')
                    && !record.command.contains('\n')
                    && record.command.chars().count() <= 400
                {
                    steps.push(step(
                        "If this exact command is routine:",
                        Some(format!(
                            "innerwarden allow {}",
                            shell_quote(&record.command)
                        )),
                        "Only this exact command is let through.",
                    ));
                } else {
                    steps.push(step(
                        "If commands like this are routine:",
                        Some("innerwarden allow \"<pattern>\"".into()),
                        "Write a pattern that matches only them; * matches any text.",
                    ));
                }
            }
            steps.truncate(2);
            steps
        }
    }
}

/// The rule behind a reason: the one the record kept, or, for a record older
/// than rule ids, the one the guard's own wording names (`concern::WORDING`).
fn primary_rule<'a>(record_rules: &'a [String], words: &str) -> Option<&'a str> {
    record_rules
        .first()
        .map(String::as_str)
        .or_else(|| concern::rule_from_words(words))
}

fn reason_short(record_rules: &[String], words: &str) -> String {
    primary_rule(record_rules, words)
        .and_then(concern::short_words)
        .map(str::to_string)
        .unwrap_or_else(|| concern::cut_words(words, 32))
}

/// What the decision reached for: from every rule it kept, or from its first
/// reason's own wording when it kept none.
fn concern_of(record: &DecisionRecord) -> concern::Concern {
    if record.rules.is_empty() {
        let derived: Vec<String> = concern::rule_from_words(&record.reason_words)
            .map(|rule| vec![rule.to_string()])
            .unwrap_or_default();
        return concern::concern_for(&derived);
    }
    concern::concern_for(&record.rules)
}

/// Everything the page needs for one decision. See the module doc for what is
/// never in here.
pub(crate) fn decision_view(record: &DecisionRecord, suppress: &SuppressConfig) -> Value {
    let mut object = Map::new();
    object.insert("id".into(), json!(record.id));
    object.insert("session".into(), json!(record.session));
    object.insert("seq".into(), json!(record.seq));
    object.insert("command".into(), json!(record.command));
    object.insert("command_whole".into(), json!(command_whole(record)));
    object.insert("channel".into(), json!(record.channel));
    opt(
        &mut object,
        "agent",
        record.agent.as_deref().map(agent_name),
    );
    opt(&mut object, "agent_id", record.agent.clone());
    opt(&mut object, "project", record.project.clone());
    object.insert("recommendation".into(), json!(record.recommendation));
    object.insert("outcome".into(), json!(record.outcome));
    object.insert("mode_at_decision".into(), json!(record.mode_at_decision));
    object.insert("outcome_key".into(), json!(record.outcome_key));
    opt(
        &mut object,
        "recorded_at",
        record.recorded_at_ms.map(rfc3339),
    );
    object.insert("decided_by".into(), json!(record.decided_by));
    opt(&mut object, "risk", record.risk);
    object.insert(
        "reason".into(),
        json!({
            "key": record.reason_key,
            "words": record.reason_words,
            "short": reason_short(&record.rules, &record.reason_words),
        }),
    );
    object.insert("reasons_more".into(), json!(record.reasons_more));
    object.insert("rules".into(), json!(record.rules));
    object.insert("categories".into(), json!(record.categories));
    object.insert("asi".into(), json!(record.asi));
    object.insert("explanation".into(), json!(record.explanation));
    object.insert("concern".into(), json!(concern_of(record).as_str()));
    object.insert(
        "story".into(),
        json!({ "happened": happened(record), "did": did(record) }),
    );
    object.insert("next".into(), json!(next_steps(record, suppress)));
    let allowed_by_you = command_whole(record)
        && suppress
            .allow
            .iter()
            .any(|pattern| glob_match(pattern, &record.command));
    object.insert("allowed_by_you".into(), json!(allowed_by_you));
    Value::Object(object)
}

fn session_json(facts: &SessionFacts) -> Value {
    let mut object = Map::new();
    opt(&mut object, "agent", facts.agent.as_deref().map(agent_name));
    object.insert("channel".into(), json!(facts.channel));
    opt(&mut object, "project", facts.project.clone());
    object.insert("decisions".into(), json!(facts.decisions));
    object.insert("flagged".into(), json!(facts.flagged));
    opt(&mut object, "first_at", facts.first_at_ms.map(rfc3339));
    opt(&mut object, "last_at", facts.last_at_ms.map(rfc3339));
    Value::Object(object)
}

/// Counts only: the allow list can hold whole commands with keys in them.
pub(crate) fn suppress_counts_json(suppress: &SuppressConfig) -> Value {
    json!({
        "allow": suppress.allow.len(),
        "mute_rules": suppress.mute_rules.len(),
        "mute_categories": suppress.mute_categories.len(),
    })
}

/// `GET /api/guard/decisions`.
pub(crate) fn decisions_json(
    page: &DecisionsPage,
    suppress: &SuppressConfig,
    now_ms: u64,
) -> Value {
    let reasons: Vec<Value> = page
        .reasons
        .iter()
        .map(|reason| {
            let mut object = Map::new();
            object.insert("key".into(), json!(reason.key));
            object.insert("words".into(), json!(reason.words));
            object.insert(
                "short".into(),
                json!(reason_short(&reason.rules, &reason.words)),
            );
            object.insert("count".into(), json!(reason.count));
            if let [only] = reason.rules.as_slice() {
                if concern::is_mutable_rule(only) {
                    object.insert("mute".into(), json!(format!("innerwarden mute {only}")));
                }
            }
            Value::Object(object)
        })
        .collect();
    let mut object = Map::new();
    object.insert("schema_version".into(), json!(SCHEMA_VERSION));
    object.insert("generated_at_ms".into(), json!(now_ms));
    object.insert(
        "items".into(),
        json!(page
            .items
            .iter()
            .map(|item| decision_view(item, suppress))
            .collect::<Vec<_>>()),
    );
    opt(&mut object, "next_cursor", page.next_cursor.clone());
    object.insert("total".into(), json!(page.total));
    object.insert("flagged_total".into(), json!(page.flagged_total));
    object.insert("by_outcome".into(), json!(page.by_outcome));
    object.insert("reasons".into(), json!(reasons));
    object.insert("reasons_distinct".into(), json!(page.reasons_distinct));
    object.insert("suppress".into(), suppress_counts_json(suppress));
    object.insert("record".into(), record_json(&page.record));
    object.insert(
        "sessions".into(),
        Value::Object(
            page.sessions
                .iter()
                .map(|(label, facts)| (label.clone(), session_json(facts)))
                .collect(),
        ),
    );
    Value::Object(object)
}

fn brief_json(brief: &DecisionBrief) -> Value {
    let mut object = Map::new();
    object.insert("id".into(), json!(brief.id));
    object.insert("command".into(), json!(one_line(&brief.command, 120)));
    object.insert("outcome_key".into(), json!(brief.outcome_key));
    opt(
        &mut object,
        "recorded_at",
        brief.recorded_at_ms.map(rfc3339),
    );
    object.insert("flagged".into(), json!(brief.flagged));
    Value::Object(object)
}

/// `GET /api/guard/decision?id=`.
pub(crate) fn decision_json(detail: &DecisionDetail, suppress: &SuppressConfig) -> Value {
    json!({
        "schema_version": SCHEMA_VERSION,
        "item": decision_view(&detail.item, suppress),
        "around": {
            "before": detail.before.iter().map(brief_json).collect::<Vec<_>>(),
            "after": detail.after.iter().map(brief_json).collect::<Vec<_>>(),
        },
        "session": session_json(&detail.session),
    })
}

/// The cursor a request carried, or an error for one this server did not
/// write. Never a silent restart from the top: that would repeat a page.
pub(crate) fn parse_cursor(value: Option<&str>) -> Result<Option<DecisionCursor>, ()> {
    match value {
        None => Ok(None),
        Some(value) => DecisionCursor::parse(value).map(Some).ok_or(()),
    }
}

// ---------------------------------------------------------------------------
// Protection
// ---------------------------------------------------------------------------

/// What Community covers on this machine, as read from local configuration.
pub(crate) struct ProtectionFacts {
    pub now_ms: u64,
    pub os: &'static str,
    pub recording: bool,
    pub outage_since_unix: Option<u64>,
    pub lost_actions: Option<u64>,
    pub jail_backend: Option<&'static str>,
    pub observe_installed: bool,
    pub alert_channels: usize,
    pub second_opinion_provider: Option<String>,
    pub suppress: SuppressConfig,
}

/// `GET /api/guard/protection`.
pub(crate) fn protection_json(facts: &ProtectionFacts) -> Value {
    let mut record = Map::new();
    record.insert("recording".into(), json!(facts.recording));
    opt(
        &mut record,
        "since",
        facts
            .outage_since_unix
            .filter(|_| !facts.recording)
            .map(|since| rfc3339(since * 1_000)),
    );
    opt(
        &mut record,
        "lost_actions",
        facts.lost_actions.filter(|_| !facts.recording),
    );
    let mut jail = Map::new();
    jail.insert("available".into(), json!(facts.jail_backend.is_some()));
    opt(&mut jail, "backend", facts.jail_backend);
    let mut second = Map::new();
    second.insert(
        "configured".into(),
        json!(facts.second_opinion_provider.is_some()),
    );
    opt(
        &mut second,
        "provider",
        facts.second_opinion_provider.clone(),
    );
    json!({
        "schema_version": SCHEMA_VERSION,
        "generated_at_ms": facts.now_ms,
        "platform": { "os": facts.os },
        "record": record,
        "jail": jail,
        "observe": { "installed": facts.observe_installed },
        "alerts": { "channels": facts.alert_channels },
        "second_opinion": second,
        "suppress": suppress_counts_json(&facts.suppress),
    })
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

/// Whether an agent's token counters are disjoint, so a bar may stack them.
///
/// Claude Code reports input, cache writes and cache reads as separate
/// counters. Codex reports cached input INSIDE input and reasoning INSIDE
/// output, so stacking them would count the same tokens twice. An agent this
/// table does not know is not stacked.
pub(crate) fn token_parts_disjoint(agent_id: &str) -> bool {
    matches!(agent_id, "claude" | "claude-code")
}

/// The token report with `parts_disjoint` on each agent.
pub(crate) fn token_intelligence_with_parts(body: &str) -> String {
    let Ok(mut value) = serde_json::from_str::<Value>(body) else {
        return body.to_string();
    };
    if let Some(agents) = value.get_mut("agents").and_then(Value::as_array_mut) {
        for agent in agents {
            let disjoint = agent
                .get("agent_id")
                .and_then(Value::as_str)
                .is_some_and(token_parts_disjoint);
            if let Some(object) = agent.as_object_mut() {
                object.insert("parts_disjoint".into(), json!(disjoint));
            }
        }
    }
    serde_json::to_string(&value).unwrap_or_else(|_| body.to_string())
}

// ---------------------------------------------------------------------------
// Agents
// ---------------------------------------------------------------------------

/// The agents payload with `guardrail.last_observed_at` set for every agent
/// the decision record NAMES, from its newest such decision. An agent no
/// decision names is left as it was: "not reported" is the honest answer
/// then, never "nothing screened".
pub(crate) fn agents_with_last_screened(
    body: &str,
    seen: &std::collections::BTreeMap<String, u64>,
) -> String {
    if seen.is_empty() {
        return body.to_string();
    }
    let Ok(mut value) = serde_json::from_str::<Value>(body) else {
        return body.to_string();
    };
    if let Some(agents) = value.get_mut("agents").and_then(Value::as_array_mut) {
        for agent in agents {
            let Some(ms) = agent
                .get("id")
                .and_then(Value::as_str)
                .and_then(|id| seen.get(id))
                .copied()
            else {
                continue;
            };
            if let Some(guardrail) = agent.get_mut("guardrail").and_then(Value::as_object_mut) {
                guardrail.insert("last_observed_at".into(), json!(rfc3339(ms)));
            }
        }
    }
    serde_json::to_string(&value).unwrap_or_else(|_| body.to_string())
}

// ---------------------------------------------------------------------------
// A parsed file, kept until the file changes
// ---------------------------------------------------------------------------

/// The identity of a file for caching: its length and modification time.
pub(crate) type FileIdentity = (u64, std::time::SystemTime);

/// A value parsed from a file, re-read only when the file's identity changes.
///
/// The Overview polls every few seconds and the graph is several megabytes;
/// parsing it once per identity rather than once per request is the whole
/// point. A file with no identity (absent, or a stat that failed) is never
/// cached: its answer is re-read every time, which is cheap for an absent file
/// and correct for a failing one.
pub(crate) struct CachedFile<T> {
    key: Option<FileIdentity>,
    value: Option<std::sync::Arc<T>>,
}

impl<T> Default for CachedFile<T> {
    fn default() -> Self {
        Self {
            key: None,
            value: None,
        }
    }
}

impl<T> CachedFile<T> {
    pub(crate) fn get_or_load<E>(
        &mut self,
        identity: Option<FileIdentity>,
        load: impl FnOnce() -> Result<T, E>,
    ) -> Result<std::sync::Arc<T>, E> {
        if let (Some(identity), Some(key), Some(value)) = (identity, self.key, &self.value) {
            if identity == key {
                return Ok(std::sync::Arc::clone(value));
            }
        }
        let value = std::sync::Arc::new(load()?);
        self.key = identity;
        self.value = identity.map(|_| std::sync::Arc::clone(&value));
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_graph::{
        DecisionChannel, DecisionContext, DecisionMode, DecisionOrigin, DecisionOutcome,
        DecisionQuery, Graph,
    };

    const NOW: u64 = 1_790_000_000_000; // 2026-09-21T14:13:20Z

    #[allow(clippy::too_many_arguments)]
    fn ingest(
        g: &mut Graph,
        seq: usize,
        command: &str,
        recommendation: &str,
        explanation: &str,
        mode: DecisionMode,
        outcome: DecisionOutcome,
        rules: &[&str],
        ms: u64,
    ) {
        g.ingest_verdict_with_origin(
            "s1",
            seq,
            command,
            &json!({"recommendation": recommendation, "explanation": explanation}),
            DecisionContext {
                mode,
                outcome,
                recorded_at_ms: Some(ms),
            },
            &DecisionOrigin {
                channel: Some(DecisionChannel::Hook),
                agent: Some("claude-code".into()),
                project: Some("my-app".into()),
                rules: rules.iter().map(|rule| rule.to_string()).collect(),
            },
        );
    }

    fn one(
        command: &str,
        recommendation: &str,
        mode: DecisionMode,
        outcome: DecisionOutcome,
        rules: &[&str],
    ) -> DecisionRecord {
        let mut g = Graph::new();
        ingest(
            &mut g,
            0,
            command,
            recommendation,
            "a reason; another reason",
            mode,
            outcome,
            rules,
            NOW - 60_000,
        );
        g.decisions_page(&DecisionQuery {
            flagged_only: false,
            ..DecisionQuery::default()
        })
        .items
        .remove(0)
    }

    fn commands(steps: &[Value]) -> Vec<String> {
        steps
            .iter()
            .filter_map(|step| step.get("command").and_then(Value::as_str))
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn rfc3339_and_weeks_are_computed_without_a_clock() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(NOW), "2026-09-21T14:13:20Z");
        assert_eq!(rfc3339(951_782_400_000), "2000-02-29T00:00:00Z");
        // 2026-09-21 is a Monday; the 27th is the Sunday of that week.
        assert_eq!(week_start(NOW).1, "2026-09-21");
        assert_eq!(week_start(NOW + 6 * DAY_MS).1, "2026-09-21");
        assert_eq!(week_start(NOW + 7 * DAY_MS).1, "2026-09-28");
    }

    #[test]
    fn next_steps_never_offer_allow_or_mute_for_a_deny() {
        for (mode, outcome) in [
            (DecisionMode::Monitor, DecisionOutcome::WouldBlock),
            (DecisionMode::Monitor, DecisionOutcome::Allowed),
            (DecisionMode::Enforce, DecisionOutcome::Allowed),
            (DecisionMode::Enforce, DecisionOutcome::Blocked),
        ] {
            let record = one(
                "cat ~/.ssh/id_rsa",
                "deny",
                mode,
                outcome,
                &["ATR-2026-001"],
            );
            let steps = next_steps(&record, &SuppressConfig::default());
            for command in commands(&steps) {
                assert!(
                    !command.contains("allow") && !command.contains("mute"),
                    "{command} offered for a deny ({mode:?}, {outcome:?})"
                );
            }
        }
        let monitor = one(
            "cat ~/.ssh/id_rsa",
            "deny",
            DecisionMode::Monitor,
            DecisionOutcome::WouldBlock,
            &[],
        );
        assert_eq!(
            commands(&next_steps(&monitor, &SuppressConfig::default())),
            ["innerwarden enforce"]
        );
    }

    #[test]
    fn no_allow_pattern_from_a_shortened_or_redacted_command() {
        let redacted = one(
            "curl -H 'Authorization: [REDACTED]' https://example.com",
            "review",
            DecisionMode::Monitor,
            DecisionOutcome::Allowed,
            &["tmp_execution"],
        );
        let steps = next_steps(&redacted, &SuppressConfig::default());
        assert_eq!(commands(&steps), ["innerwarden allow \"<pattern>\""]);
        let long = format!("bash /tmp/{}", "x".repeat(200));
        let shortened = one(
            &long,
            "review",
            DecisionMode::Monitor,
            DecisionOutcome::Allowed,
            &["tmp_execution"],
        );
        assert!(shortened.command_shortened);
        assert_eq!(
            commands(&next_steps(&shortened, &SuppressConfig::default())),
            ["innerwarden allow \"<pattern>\""]
        );
        // A glob in the command would widen an exact allow: a pattern instead.
        let globbed = one(
            "rm /tmp/*.log",
            "review",
            DecisionMode::Monitor,
            DecisionOutcome::Allowed,
            &["tmp_execution"],
        );
        assert_eq!(
            commands(&next_steps(&globbed, &SuppressConfig::default())),
            ["innerwarden allow \"<pattern>\""]
        );
    }

    #[test]
    fn a_whole_review_command_offers_an_exact_allow_quoted_for_the_shell() {
        let record = one(
            "bash /tmp/it's.sh",
            "review",
            DecisionMode::Enforce,
            DecisionOutcome::Allowed,
            &["tmp_execution"],
        );
        assert_eq!(
            commands(&next_steps(&record, &SuppressConfig::default())),
            ["innerwarden allow 'bash /tmp/it'\\''s.sh'"]
        );
    }

    #[test]
    fn a_single_atr_rule_offers_a_mute_and_monitor_offers_enforce_first() {
        let record = one(
            "x",
            "review",
            DecisionMode::Monitor,
            DecisionOutcome::WouldBlock,
            &["ATR-2026-051"],
        );
        assert_eq!(
            commands(&next_steps(&record, &SuppressConfig::default())),
            ["innerwarden enforce", "innerwarden mute ATR-2026-051"]
        );
        // Two rules: one mute is not enough, so no mute is offered.
        let two = one(
            "x",
            "review",
            DecisionMode::Enforce,
            DecisionOutcome::Allowed,
            &["ATR-1", "ATR-2"],
        );
        assert!(!commands(&next_steps(&two, &SuppressConfig::default()))
            .iter()
            .any(|c| c.contains("mute")));
    }

    #[test]
    fn what_you_can_do_says_something_for_every_outcome() {
        let cases = [
            (DecisionMode::Enforce, DecisionOutcome::Blocked, "deny"),
            (DecisionMode::Monitor, DecisionOutcome::WouldBlock, "deny"),
            (DecisionMode::Monitor, DecisionOutcome::Allowed, "review"),
            (DecisionMode::Monitor, DecisionOutcome::Allowed, "deny"),
            (DecisionMode::Check, DecisionOutcome::Screened, "deny"),
        ];
        for (mode, outcome, verdict) in cases {
            let record = one("x", verdict, mode, outcome, &["tmp_execution"]);
            assert!(
                !next_steps(&record, &SuppressConfig::default()).is_empty(),
                "{mode:?} {outcome:?}"
            );
        }
        let mut g = Graph::new();
        g.ingest_verdict("s1", 0, "old", &json!({"recommendation": "deny"}));
        let old = g.decisions_page(&DecisionQuery::default()).items.remove(0);
        assert_eq!(old.outcome_key, "unplaced");
        assert!(!next_steps(&old, &SuppressConfig::default()).is_empty());
    }

    #[test]
    fn a_command_the_user_has_since_allowed_says_so() {
        let record = one(
            "make build",
            "review",
            DecisionMode::Monitor,
            DecisionOutcome::Allowed,
            &["tmp_execution"],
        );
        let suppress = SuppressConfig {
            allow: vec!["make *".into()],
            ..SuppressConfig::default()
        };
        let view = decision_view(&record, &suppress);
        assert_eq!(view["allowed_by_you"], true);
        assert!(commands(view["next"].as_array().unwrap()).is_empty());
        // The pattern itself never leaves the process.
        assert!(!view.to_string().contains("make *"));
    }

    #[test]
    fn the_story_names_only_what_the_record_holds() {
        let record = one(
            "cat ~/.ssh/config",
            "deny",
            DecisionMode::Monitor,
            DecisionOutcome::WouldBlock,
            &["sensitive_credential_read"],
        );
        let view = decision_view(&record, &SuppressConfig::default());
        assert_eq!(view["agent"], "Claude Code");
        assert_eq!(view["concern"], "credential_read");
        assert_eq!(view["reason"]["short"], "credential path");
        assert_eq!(
            view["story"]["did"],
            "The rules said deny. Monitor mode records and does not refuse, so it ran."
        );
        let happened = view["story"]["happened"].as_array().unwrap();
        assert_eq!(happened[0]["text"], "Claude Code asked to run this");
        assert_eq!(happened[2], json!({"kind": "code", "text": "my-app"}));
        assert_eq!(happened[4]["kind"], "time");
        // One rule on record: no "more reasons", even though the explanation
        // carried two clauses.
        assert_eq!(happened[5]["text"], ". The guard flagged it: a reason.");
        // No agent recorded: no agent named.
        let mut g = Graph::new();
        g.ingest_verdict_with_context(
            "s1",
            0,
            "rm -rf /",
            &json!({"recommendation": "deny", "explanation": "x"}),
            DecisionContext {
                mode: DecisionMode::Enforce,
                outcome: DecisionOutcome::Blocked,
                recorded_at_ms: Some(NOW),
            },
        );
        let item = g.decisions_page(&DecisionQuery::default()).items.remove(0);
        let view = decision_view(&item, &SuppressConfig::default());
        assert!(view.get("agent").is_none());
        assert_eq!(
            view["story"]["happened"][0]["text"],
            "An agent asked, through its shell hook, to run this"
        );
        assert_eq!(
            view["story"]["did"],
            "The rules said deny, and the guard refused it before it ran."
        );
    }

    #[test]
    fn an_older_record_is_read_by_the_guards_own_wording() {
        let mut g = Graph::new();
        g.ingest_verdict_with_context(
            "s1",
            0,
            "cat ~/.ssh/config",
            &json!({"recommendation": "deny", "explanation": "reads sensitive credential path: `.ssh/`"}),
            DecisionContext {
                mode: DecisionMode::Monitor,
                outcome: DecisionOutcome::WouldBlock,
                recorded_at_ms: Some(NOW),
            },
        );
        let item = g.decisions_page(&DecisionQuery::default()).items.remove(0);
        let view = decision_view(&item, &SuppressConfig::default());
        assert_eq!(view["concern"], "credential_read");
        assert_eq!(view["reason"]["short"], "credential path");
        // Nothing is invented into the record's own rule list, and no mute is
        // offered on a rule the record did not keep.
        assert_eq!(view["rules"], json!([]));
        assert!(!view.to_string().contains("innerwarden mute"));
        // Words the guard never writes are cut, not guessed.
        let mut other = Graph::new();
        other.ingest_verdict_with_context(
            "s1",
            0,
            "x",
            &json!({"recommendation": "review", "explanation": "a sentence nobody in this product writes"}),
            DecisionContext::default(),
        );
        let item = other
            .decisions_page(&DecisionQuery::default())
            .items
            .remove(0);
        let view = decision_view(&item, &SuppressConfig::default());
        assert_eq!(view["concern"], "other");
        assert_eq!(view["reason"]["short"], "a sentence nobody in this…");
    }

    fn log_text() -> String {
        [
            json!({"kind": "guard.blocked", "ts": 1_789_000_000, "outcome": "blocked", "detail": "rm -rf /"}).to_string(),
            json!({"kind": "guard.blocked", "ts": 1_789_900_000, "outcome": "would_block", "detail": "x"}).to_string(),
            json!({"kind": "guard.suppression_changed", "ts": 1_789_900_100, "action": "allow_added", "pattern": "secret-token-PATTERN *"}).to_string(),
            "{\"kind\":\"guard.blocked\",\"ts\":17".into(),
            json!({"kind": "guard.attempt", "ts": 1_789_950_000, "channel": "telegram", "sender": "user 12345", "surface": "conversation", "detail": "run the script that deletes the backups", "decider": "model_refused", "enforced": false, "recommendation": "deny", "risk_score": 80}).to_string(),
        ]
        .join("\n")
    }

    #[test]
    fn a_malformed_event_log_line_is_counted_not_fatal() {
        let log = parse_event_log(&log_text());
        assert!(log.readable);
        assert_eq!(log.unparsable_lines, 1);
        assert_eq!(log.blocked.len(), 1);
        assert_eq!(log.would_block.len(), 1);
        assert_eq!(log.attempts.len(), 1);
        assert_eq!(log.suppression_changes, 1);
    }

    #[test]
    fn history_never_serves_a_suppression_pattern() {
        let log = parse_event_log(&log_text());
        let body = history_json(&log, NOW).to_string();
        assert!(!body.contains("secret-token-PATTERN"), "{body}");
        let attempts = attempts_json(&log, None, 10).to_string();
        assert!(!attempts.contains("secret-token-PATTERN"));
        // Anti-vacuous: the history did read the log.
        let history = history_json(&log, NOW);
        assert_eq!(history["refusals"]["blocked"], 1);
        assert_eq!(history["suppression_changes"], 1);
        assert_eq!(history["messages"]["recorded"], 1);
    }

    #[test]
    fn history_weeks_cover_the_log_and_add_up() {
        let log = parse_event_log(&log_text());
        let history = history_json(&log, NOW);
        let weeks = history["refusals"]["weeks"].as_array().unwrap();
        assert!(!weeks.is_empty() && weeks.len() <= MAX_WEEKS as usize);
        let blocked: u64 = weeks
            .iter()
            .map(|week| week["blocked"].as_u64().unwrap())
            .sum();
        let would: u64 = weeks
            .iter()
            .map(|week| week["would_block"].as_u64().unwrap())
            .sum();
        assert_eq!((blocked, would), (1, 1));
        assert_eq!(weeks.last().unwrap()["start"], "2026-09-21");
    }

    #[test]
    fn protection_serves_counts_only() {
        let facts = ProtectionFacts {
            now_ms: NOW,
            os: "macos",
            recording: true,
            outage_since_unix: None,
            lost_actions: None,
            jail_backend: Some("sandbox-exec"),
            observe_installed: false,
            alert_channels: 1,
            second_opinion_provider: Some("azure".into()),
            suppress: SuppressConfig {
                allow: vec!["deploy --token sk-live-SECRET".into()],
                mute_rules: vec!["ATR-2026-051".into()],
                mute_categories: vec![],
            },
        };
        let body = protection_json(&facts);
        let text = body.to_string();
        assert!(!text.contains("sk-live-SECRET"));
        assert!(!text.contains("ATR-2026-051"));
        assert_eq!(
            body["suppress"],
            json!({"allow": 1, "mute_rules": 1, "mute_categories": 0})
        );
        assert_eq!(
            body["jail"],
            json!({"available": true, "backend": "sandbox-exec"})
        );
        assert!(body["record"].get("since").is_none());
    }

    fn lane_facts<'a>(
        tally: &'a Tally,
        record: &'a RecordSpan,
        mode: &'a str,
        log: &'a EventLog,
    ) -> LaneFacts<'a> {
        LaneFacts {
            now_ms: NOW,
            tally,
            record,
            guard_mode: mode,
            observe_installed: false,
            log,
        }
    }

    #[test]
    fn no_agent_and_no_record_is_no_source_not_zero() {
        let g = Graph::new();
        let tally = g.agent_actions_tally(0);
        let record = g.record_span();
        let log = EventLog::default();
        let lanes = lanes_json(&lane_facts(&tally, &record, "not_configured", &log));
        assert_eq!(lanes["agent_actions"]["availability"], "no_source");
        assert!(lanes["agent_actions"].get("count").is_none());
        assert_eq!(lanes["agent_messages"]["availability"], "no_source");
        let connected = lanes_json(&lane_facts(&tally, &record, "monitor", &log));
        assert_eq!(connected["agent_actions"]["count"], 0);
        assert_eq!(
            connected["agent_actions"]["sentence"],
            "Connected. Nothing screened yet."
        );
    }

    #[test]
    fn server_attacks_is_always_no_source() {
        let mut g = Graph::new();
        ingest(
            &mut g,
            0,
            "x",
            "deny",
            "r",
            DecisionMode::Enforce,
            DecisionOutcome::Blocked,
            &[],
            NOW - 1,
        );
        let tally = g.agent_actions_tally(NOW - LANE_WINDOW_MS);
        let record = g.record_span();
        let log = parse_event_log(&log_text());
        let lanes = lanes_json(&lane_facts(&tally, &record, "enforce", &log));
        assert_eq!(lanes["server_attacks"]["availability"], "no_source");
        assert!(lanes["server_attacks"].get("count").is_none());
    }

    #[test]
    fn agent_card_sends_since_only_when_the_record_starts_inside_the_window() {
        let log = EventLog::default();
        let mut g = Graph::new();
        ingest(
            &mut g,
            0,
            "bash /tmp/a",
            "review",
            "r",
            DecisionMode::Monitor,
            DecisionOutcome::Allowed,
            &["tmp_execution"],
            NOW - 2 * DAY_MS,
        );
        ingest(
            &mut g,
            1,
            "ls",
            "allow",
            "",
            DecisionMode::Monitor,
            DecisionOutcome::Allowed,
            &[],
            NOW - DAY_MS,
        );
        let tally = g.agent_actions_tally(NOW - LANE_WINDOW_MS);
        let record = g.record_span();
        let lanes = lanes_json(&lane_facts(&tally, &record, "monitor", &log));
        let card = &lanes["agent_actions"];
        assert_eq!(card["since"], rfc3339(NOW - 2 * DAY_MS));
        assert_eq!(card["count"], 2);
        let parts = card["breakdown"].as_array().unwrap();
        let sum: u64 = parts
            .iter()
            .map(|part| part["count"].as_u64().unwrap())
            .sum();
        assert_eq!(sum, 2);
        assert_eq!(card["latest"]["case_id"], "cmd:s1:0");
        assert_eq!(card["latest"]["title"], "Claude Code tried bash /tmp/a");
        assert!(card["sentence"].as_str().unwrap().contains("monitor mode"));

        // A record older than the window: no `since`.
        ingest(
            &mut g,
            2,
            "old",
            "allow",
            "",
            DecisionMode::Monitor,
            DecisionOutcome::Allowed,
            &[],
            NOW - 30 * DAY_MS,
        );
        let tally = g.agent_actions_tally(NOW - LANE_WINDOW_MS);
        let record = g.record_span();
        let lanes = lanes_json(&lane_facts(&tally, &record, "monitor", &log));
        assert!(lanes["agent_actions"].get("since").is_none());
    }

    #[test]
    fn messages_count_the_last_seven_days_of_attempts() {
        let g = Graph::new();
        let tally = g.agent_actions_tally(0);
        let record = g.record_span();
        let old = parse_event_log(&log_text());
        // The attempt is two days before NOW's week... check the window both ways.
        let within = EventLog {
            attempts: vec![Attempt {
                ts: NOW / 1_000 - 3_600,
                ..old.attempts[0].clone()
            }],
            ..old.clone()
        };
        let lanes = lanes_json(&lane_facts(&tally, &record, "monitor", &within));
        assert_eq!(lanes["agent_messages"]["count"], 1);
        assert_eq!(
            lanes["agent_messages"]["breakdown"][0]["key"],
            "declined_by_agent"
        );
        let stale = EventLog {
            attempts: vec![Attempt {
                ts: NOW / 1_000 - 10 * 86_400,
                ..old.attempts[0].clone()
            }],
            ..old
        };
        let lanes = lanes_json(&lane_facts(&tally, &record, "monitor", &stale));
        assert_eq!(lanes["agent_messages"]["count"], 0);
        assert!(lanes["agent_messages"].get("breakdown").is_none());
        assert!(lanes["agent_messages"]["latest"]["title"]
            .as_str()
            .unwrap()
            .starts_with("Someone on Telegram"));
        // The sender stays out of the lane.
        assert!(!lanes.to_string().contains("12345"));
    }

    #[test]
    fn project_is_a_basename_never_a_path() {
        let mut g = Graph::new();
        g.ingest_verdict_with_origin(
            "s1",
            0,
            "x",
            &json!({"recommendation": "deny"}),
            DecisionContext::default(),
            &DecisionOrigin {
                project: Some("/Users/someone/secret-client/my-app".into()),
                ..DecisionOrigin::default()
            },
        );
        let item = g.decisions_page(&DecisionQuery::default()).items.remove(0);
        let view = decision_view(&item, &SuppressConfig::default());
        assert!(view.get("project").is_none());
        assert!(!view.to_string().contains("secret-client"));
    }

    #[test]
    fn cached_graph_is_not_reparsed_when_the_file_is_unchanged() {
        let mut cache: CachedFile<usize> = CachedFile::default();
        let identity = Some((10u64, std::time::UNIX_EPOCH));
        let mut loads = 0;
        for _ in 0..3 {
            let value = cache
                .get_or_load::<()>(identity, || {
                    loads += 1;
                    Ok(7)
                })
                .unwrap();
            assert_eq!(*value, 7);
        }
        assert_eq!(loads, 1);
        // A changed identity reloads; no identity never caches.
        let changed = Some((11u64, std::time::UNIX_EPOCH));
        cache
            .get_or_load::<()>(changed, || {
                loads += 1;
                Ok(8)
            })
            .unwrap();
        cache
            .get_or_load::<()>(None, || {
                loads += 1;
                Ok(9)
            })
            .unwrap();
        cache
            .get_or_load::<()>(None, || {
                loads += 1;
                Ok(9)
            })
            .unwrap();
        assert_eq!(loads, 4);
        // A failed load keeps nothing it did not read.
        let mut failing: CachedFile<usize> = CachedFile::default();
        assert!(failing
            .get_or_load(identity, || Err::<usize, _>("bad"))
            .is_err());
        assert_eq!(*failing.get_or_load::<()>(identity, || Ok(1)).unwrap(), 1);
    }

    #[test]
    fn last_screened_is_set_only_for_an_agent_the_record_names() {
        let body = json!({"agents": [
            {"id": "claude-code", "guardrail": {"mode": "monitor"}},
            {"id": "cursor", "guardrail": {"mode": "enforce"}},
        ]})
        .to_string();
        let mut seen = std::collections::BTreeMap::new();
        seen.insert("claude-code".to_string(), NOW);
        let out: Value = serde_json::from_str(&agents_with_last_screened(&body, &seen)).unwrap();
        assert_eq!(
            out["agents"][0]["guardrail"]["last_observed_at"],
            rfc3339(NOW)
        );
        assert!(out["agents"][1]["guardrail"]
            .get("last_observed_at")
            .is_none());
        assert_eq!(agents_with_last_screened(&body, &Default::default()), body);
    }

    #[test]
    fn token_parts_are_stacked_only_where_they_are_disjoint() {
        let body =
            json!({"agents": [{"agent_id": "claude"}, {"agent_id": "codex"}, {"agent_id": "new"}]})
                .to_string();
        let out: Value = serde_json::from_str(&token_intelligence_with_parts(&body)).unwrap();
        assert_eq!(out["agents"][0]["parts_disjoint"], true);
        assert_eq!(out["agents"][1]["parts_disjoint"], false);
        assert_eq!(out["agents"][2]["parts_disjoint"], false);
        assert_eq!(token_intelligence_with_parts("not json"), "not json");
    }
}
