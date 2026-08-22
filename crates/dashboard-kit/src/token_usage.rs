//! Privacy-preserving token intelligence from retained local agent history.
//!
//! The collector intentionally reads only numeric usage counters from the
//! supported retained local history roots below. It never returns session/message IDs,
//! prompts, code, file paths, account data, process data, or parser errors.
//! Local history is incomplete by nature, so these values are observability
//! counters rather than a billing statement.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_FILES_PER_SOURCE: usize = 4_096;
const MAX_DIRECTORIES_PER_SOURCE: usize = 8_192;
const MAX_ENTRIES_PER_SOURCE: usize = 100_000;
const MAX_BYTES_PER_SOURCE: u64 = 64 * 1024 * 1024;
const MAX_BYTES_PER_FILE: u64 = 32 * 1024 * 1024;
const MAX_CODEX_SESSION_PREFIX_BYTES: u64 = 64 * 1024;
const MAX_BYTES_PER_LINE: usize = 2 * 1024 * 1024;
const MAX_USAGE_RECORDS_PER_SOURCE: usize = 250_000;

const RETAINED_HISTORY_NOTE: &str =
    "Provider-reported counters found in retained local history; partial and not a billing statement.";
const UNSUPPORTED_NOTE: &str =
    "No supported local token source is available; no billing estimate is inferred.";
const LOADING_NOTE: &str =
    "Scanning numeric counters from retained local history; no prompts or code are collected.";
const NO_DATA_NOTE: &str = "No numeric token counters were found in the available local history.";
const ERROR_NOTE: &str = "Local history could not be read completely; no token value is inferred.";

/// Thread-safe dashboard snapshot returned by [`spawn_refresher`].
pub type SharedTokenIntelligence = Arc<RwLock<TokenIntelligence>>;

/// Availability of the aggregate report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportAvailability {
    Loading,
    Partial,
    NoData,
    Error,
}

/// Availability of one provider's local counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentAvailability {
    Loading,
    Available,
    NoData,
    Unsupported,
    Error,
}

/// Numeric counters. Cached input and reasoning output are subsets for Codex;
/// callers must not add them to `total_tokens` again.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TokenCounters {
    #[serde(serialize_with = "decimal_string::required")]
    pub total_tokens: u64,
    #[serde(serialize_with = "decimal_string::required")]
    pub input_tokens: u64,
    #[serde(serialize_with = "decimal_string::required")]
    pub output_tokens: u64,
    #[serde(serialize_with = "decimal_string::required")]
    pub cache_read_input_tokens: u64,
    #[serde(serialize_with = "decimal_string::required")]
    pub cached_input_tokens: u64,
    #[serde(serialize_with = "decimal_string::required")]
    pub cache_creation_input_tokens: u64,
    #[serde(serialize_with = "decimal_string::required")]
    pub reasoning_output_tokens: u64,
}

/// Honest provenance attached to every provider row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TokenProvenance {
    pub source: &'static str,
    pub quality: &'static str,
    pub note: &'static str,
}

/// One provider's token usage. Unsupported or unavailable counters serialize as
/// `null`, never as a misleading zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentTokenUsage {
    pub agent_id: &'static str,
    pub display_name: &'static str,
    pub availability: AgentAvailability,
    #[serde(serialize_with = "decimal_string::optional")]
    pub total_tokens: Option<u64>,
    #[serde(serialize_with = "decimal_string::optional")]
    pub input_tokens: Option<u64>,
    #[serde(serialize_with = "decimal_string::optional")]
    pub output_tokens: Option<u64>,
    #[serde(serialize_with = "decimal_string::optional")]
    pub cache_read_input_tokens: Option<u64>,
    #[serde(serialize_with = "decimal_string::optional")]
    pub cached_input_tokens: Option<u64>,
    #[serde(serialize_with = "decimal_string::optional")]
    pub cache_creation_input_tokens: Option<u64>,
    #[serde(serialize_with = "decimal_string::optional")]
    pub reasoning_output_tokens: Option<u64>,
    pub sessions: Option<u64>,
    pub last_observed_at_ms: Option<u64>,
    pub provenance: TokenProvenance,
}

/// Versioned API payload for the dashboard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TokenIntelligence {
    pub schema_version: u32,
    pub generated_at_ms: u64,
    pub scope: &'static str,
    pub availability: ReportAvailability,
    pub totals: Option<TokenCounters>,
    pub agents: Vec<AgentTokenUsage>,
}

/// JavaScript numbers cannot exactly represent all `u64` values. The API emits
/// decimal strings so the React client can format even very large counters with
/// `BigInt` and never silently round observed usage.
mod decimal_string {
    use serde::Serializer;

    pub fn required<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn optional<S>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(value) => serializer.serialize_some(&value.to_string()),
            None => serializer.serialize_none(),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct ClaudeUsage {
    input: u64,
    output: u64,
    cache_read: u64,
    cache_creation: u64,
}

/// Narrow wire models deliberately omit every non-usage field. Serde skips
/// prompt and tool content without allocating it into an intermediate JSON tree.
#[derive(Debug, Deserialize)]
struct ClaudeLine {
    #[serde(rename = "type")]
    kind: Option<String>,
    message: Option<ClaudeMessage>,
}

#[derive(Debug, Deserialize)]
struct ClaudeMessage {
    id: Option<String>,
    usage: Option<ClaudeUsageWire>,
}

#[derive(Debug, Deserialize)]
struct ClaudeUsageWire {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    cache_read_input_tokens: Option<u64>,
    cache_creation_input_tokens: Option<u64>,
}

impl ClaudeUsage {
    fn keep_larger_snapshot(&mut self, other: &Self) {
        // Repeated message IDs are updated snapshots, not independent usage.
        // Keep one real observation; per-field maxima could synthesize a record
        // that the provider never emitted.
        if other.total() >= self.total() {
            *self = other.clone();
        }
    }

    fn total(&self) -> u64 {
        self.input
            .saturating_add(self.output)
            .saturating_add(self.cache_read)
            .saturating_add(self.cache_creation)
    }
}

#[derive(Debug, Clone, Default)]
struct CodexUsage {
    input: u64,
    output: u64,
    cached_input: u64,
    reasoning_output: u64,
    total: u64,
}

#[derive(Debug, Deserialize)]
struct CodexLine {
    #[serde(rename = "type")]
    kind: Option<String>,
    payload: Option<CodexPayload>,
}

#[derive(Debug, Deserialize)]
struct CodexPayload {
    #[serde(rename = "type")]
    kind: Option<String>,
    id: Option<String>,
    info: Option<CodexInfo>,
}

#[derive(Debug, Deserialize)]
struct CodexInfo {
    total_token_usage: Option<CodexUsageWire>,
}

#[derive(Debug, Deserialize)]
struct CodexUsageWire {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    cached_input_tokens: Option<u64>,
    reasoning_output_tokens: Option<u64>,
    total_tokens: Option<u64>,
}

impl CodexUsage {
    fn keep_larger_snapshot(&mut self, other: &Self) {
        // `total_token_usage` is cumulative. Select one complete provider
        // snapshot per session instead of combining fields across observations.
        if other.total >= self.total {
            *self = other.clone();
        }
    }
}

#[derive(Debug)]
struct Candidate {
    path: PathBuf,
    len: u64,
    modified_ms: Option<u64>,
}

#[derive(Debug, Default)]
struct Discovery {
    files: Vec<Candidate>,
    had_error: bool,
    truncated: bool,
}

#[derive(Debug, Default)]
struct ScanSummary {
    sessions: u64,
    last_observed_at_ms: Option<u64>,
    had_error: bool,
    truncated: bool,
}

/// Collect numeric token counters from the exact Claude Code and Codex local
/// history roots below `home`. Cursor is represented honestly as unsupported;
/// no undocumented database or inferred billing data is read.
pub fn collect(home: &Path) -> TokenIntelligence {
    let claude = collect_claude(home);
    let codex = collect_codex(home);
    let cursor = unsupported_agent("cursor", "Cursor");

    let numeric_agents = [&claude, &codex]
        .into_iter()
        .filter_map(agent_counters)
        .collect::<Vec<_>>();
    let totals = if numeric_agents.is_empty() {
        None
    } else {
        Some(
            numeric_agents
                .into_iter()
                .fold(TokenCounters::default(), |mut total, counters| {
                    total.total_tokens = total.total_tokens.saturating_add(counters.total_tokens);
                    total.input_tokens = total.input_tokens.saturating_add(counters.input_tokens);
                    total.output_tokens =
                        total.output_tokens.saturating_add(counters.output_tokens);
                    total.cache_read_input_tokens = total
                        .cache_read_input_tokens
                        .saturating_add(counters.cache_read_input_tokens);
                    total.cached_input_tokens = total
                        .cached_input_tokens
                        .saturating_add(counters.cached_input_tokens);
                    total.cache_creation_input_tokens = total
                        .cache_creation_input_tokens
                        .saturating_add(counters.cache_creation_input_tokens);
                    total.reasoning_output_tokens = total
                        .reasoning_output_tokens
                        .saturating_add(counters.reasoning_output_tokens);
                    total
                }),
        )
    };

    // Retained local history is never claimed to be a complete provider ledger.
    let availability = if totals.is_some() {
        ReportAvailability::Partial
    } else if [&claude, &codex]
        .iter()
        .any(|agent| agent.availability == AgentAvailability::Error)
    {
        ReportAvailability::Error
    } else {
        ReportAvailability::NoData
    };

    TokenIntelligence {
        schema_version: 1,
        generated_at_ms: epoch_ms(SystemTime::now()).unwrap_or(0),
        scope: "available_local_history",
        availability,
        totals,
        agents: vec![claude, codex, cursor],
    }
}

/// Start a background collector without delaying dashboard startup. The API
/// initially returns an explicit `loading` snapshot; the first scan begins at
/// once and subsequent refreshes replace it atomically. A poisoned lock is
/// recovered without exposing an error string through the API.
pub fn spawn_refresher(home: PathBuf, refresh_every: Duration) -> SharedTokenIntelligence {
    let shared = Arc::new(RwLock::new(loading_report()));
    let writer = Arc::clone(&shared);
    let collector = std::thread::Builder::new()
        .name("iw-token-intelligence".into())
        .spawn(move || loop {
            let next = collect(&home);
            match writer.write() {
                Ok(mut report) => *report = next,
                Err(poisoned) => *poisoned.into_inner() = next,
            }
            if refresh_every.is_zero() {
                break;
            }
            std::thread::sleep(refresh_every);
        });
    if collector.is_err() {
        let failed = TokenIntelligence {
            schema_version: 1,
            generated_at_ms: epoch_ms(SystemTime::now()).unwrap_or(0),
            scope: "available_local_history",
            availability: ReportAvailability::Error,
            totals: None,
            agents: vec![
                no_data_agent("claude", "Claude Code", true, false),
                no_data_agent("codex", "Codex", true, false),
                unsupported_agent("cursor", "Cursor"),
            ],
        };
        match shared.write() {
            Ok(mut report) => *report = failed,
            Err(poisoned) => *poisoned.into_inner() = failed,
        }
    }
    shared
}

fn loading_report() -> TokenIntelligence {
    fn loading_agent(agent_id: &'static str, display_name: &'static str) -> AgentTokenUsage {
        AgentTokenUsage {
            agent_id,
            display_name,
            availability: AgentAvailability::Loading,
            total_tokens: None,
            input_tokens: None,
            output_tokens: None,
            cache_read_input_tokens: None,
            cached_input_tokens: None,
            cache_creation_input_tokens: None,
            reasoning_output_tokens: None,
            sessions: None,
            last_observed_at_ms: None,
            provenance: TokenProvenance {
                source: "local_session_log",
                quality: "loading",
                note: LOADING_NOTE,
            },
        }
    }

    TokenIntelligence {
        schema_version: 1,
        generated_at_ms: epoch_ms(SystemTime::now()).unwrap_or(0),
        scope: "available_local_history",
        availability: ReportAvailability::Loading,
        totals: None,
        agents: vec![
            loading_agent("claude", "Claude Code"),
            loading_agent("codex", "Codex"),
            unsupported_agent("cursor", "Cursor"),
        ],
    }
}

/// Build a safe row for an agent without a supported local token source.
pub fn unsupported_agent(agent_id: &'static str, display_name: &'static str) -> AgentTokenUsage {
    AgentTokenUsage {
        agent_id,
        display_name,
        availability: AgentAvailability::Unsupported,
        total_tokens: None,
        input_tokens: None,
        output_tokens: None,
        cache_read_input_tokens: None,
        cached_input_tokens: None,
        cache_creation_input_tokens: None,
        reasoning_output_tokens: None,
        sessions: None,
        last_observed_at_ms: None,
        provenance: TokenProvenance {
            source: "not_available",
            quality: "unsupported",
            note: UNSUPPORTED_NOTE,
        },
    }
}

fn collect_claude(home: &Path) -> AgentTokenUsage {
    let Some(root) = safe_source_root(home, &[".claude", "projects"]) else {
        return no_data_agent("claude", "Claude Code", false, false);
    };
    let discovery = discover_jsonl(std::slice::from_ref(&root));
    let mut messages: HashMap<String, ClaudeUsage> = HashMap::new();
    let mut sessions: HashSet<PathBuf> = HashSet::new();
    let mut scan = ScanSummary {
        had_error: discovery.had_error,
        truncated: discovery.truncated,
        ..ScanSummary::default()
    };
    let mut remaining = MAX_BYTES_PER_SOURCE;

    for candidate in discovery.files {
        if remaining == 0 {
            scan.truncated = true;
            break;
        }
        let allowance = candidate.len.min(MAX_BYTES_PER_FILE).min(remaining);
        remaining = remaining.saturating_sub(allowance);
        if allowance < candidate.len {
            scan.truncated = true;
        }

        let mut saw_usage = false;
        let mut record_limit_hit = false;
        match open_source_file(&candidate.path) {
            Ok(file) => {
                let (error, truncated) =
                    for_each_json_line::<ClaudeLine>(file, candidate.len, allowance, |line| {
                        if let Some((message_id, usage)) = claude_usage(line) {
                            saw_usage = true;
                            if let Some(existing) = messages.get_mut(&message_id) {
                                existing.keep_larger_snapshot(&usage);
                            } else if messages.len() < MAX_USAGE_RECORDS_PER_SOURCE {
                                messages.insert(message_id, usage);
                            } else {
                                record_limit_hit = true;
                            }
                        }
                    });
                scan.had_error |= error;
                scan.truncated |= truncated || record_limit_hit;
            }
            Err(_) => scan.had_error = true,
        }
        if saw_usage {
            sessions.insert(claude_session_key(&root, &candidate.path));
            scan.last_observed_at_ms = max_option(scan.last_observed_at_ms, candidate.modified_ms);
        }
    }

    if messages.is_empty() {
        let failed = scan.had_error || scan.truncated;
        return no_data_agent("claude", "Claude Code", failed, !failed);
    }

    let mut counters = TokenCounters::default();
    for usage in messages.values() {
        counters.total_tokens = counters.total_tokens.saturating_add(usage.total());
        counters.input_tokens = counters.input_tokens.saturating_add(usage.input);
        counters.output_tokens = counters.output_tokens.saturating_add(usage.output);
        counters.cache_read_input_tokens = counters
            .cache_read_input_tokens
            .saturating_add(usage.cache_read);
        counters.cache_creation_input_tokens = counters
            .cache_creation_input_tokens
            .saturating_add(usage.cache_creation);
    }
    scan.sessions = sessions.len().try_into().unwrap_or(u64::MAX);
    available_agent(
        "claude",
        "Claude Code",
        counters,
        scan,
        SupportedDimensions {
            cache_read: true,
            cached_input: false,
            cache_creation: true,
            reasoning_output: false,
        },
    )
}

fn collect_codex(home: &Path) -> AgentTokenUsage {
    let roots = [
        safe_source_root(home, &[".codex", "sessions"]),
        safe_source_root(home, &[".codex", "archived_sessions"]),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    if roots.is_empty() {
        return no_data_agent("codex", "Codex", false, false);
    }
    let discovery = discover_jsonl(&roots);
    let mut sessions: HashMap<String, CodexUsage> = HashMap::new();
    let mut observed_files: HashMap<String, Option<u64>> = HashMap::new();
    let mut scan = ScanSummary {
        had_error: discovery.had_error,
        truncated: discovery.truncated,
        ..ScanSummary::default()
    };
    let mut remaining = MAX_BYTES_PER_SOURCE;

    for candidate in discovery.files {
        if remaining == 0 {
            scan.truncated = true;
            break;
        }
        let (prefix_allowance, allowance) = codex_file_budgets(candidate.len, remaining);
        let file_budget = prefix_allowance.saturating_add(allowance);
        remaining = remaining.saturating_sub(file_budget);
        if file_budget < candidate.len {
            scan.truncated = true;
        }

        let mut session_id = (prefix_allowance > 0)
            .then(|| codex_session_id_from_prefix(&candidate.path, prefix_allowance))
            .flatten();
        let mut cumulative = CodexUsage::default();
        let mut saw_usage = false;
        match open_source_file(&candidate.path) {
            Ok(file) => {
                let (error, truncated) =
                    for_each_json_line::<CodexLine>(file, candidate.len, allowance, |value| {
                        if session_id.is_none() {
                            session_id = codex_session_id(&value);
                        }
                        if let Some(usage) = codex_usage(&value) {
                            saw_usage = true;
                            cumulative.keep_larger_snapshot(&usage);
                        }
                    });
                scan.had_error |= error;
                scan.truncated |= truncated;
            }
            Err(_) => scan.had_error = true,
        }

        if saw_usage {
            if let Some(id) = session_id {
                sessions
                    .entry(id.clone())
                    .or_default()
                    .keep_larger_snapshot(&cumulative);
                let observed = observed_files.entry(id).or_insert(None);
                *observed = max_option(*observed, candidate.modified_ms);
            } else {
                // Without the provider's session ID, cumulative snapshots cannot
                // be deduplicated safely, so fail closed instead of inflating use.
                scan.had_error = true;
            }
        }
    }

    if sessions.is_empty() {
        let failed = scan.had_error || scan.truncated;
        return no_data_agent("codex", "Codex", failed, !failed);
    }

    let mut counters = TokenCounters::default();
    for usage in sessions.values() {
        counters.total_tokens = counters.total_tokens.saturating_add(usage.total);
        counters.input_tokens = counters.input_tokens.saturating_add(usage.input);
        counters.output_tokens = counters.output_tokens.saturating_add(usage.output);
        // Both values are provider-reported subsets of input/output respectively.
        counters.cached_input_tokens = counters
            .cached_input_tokens
            .saturating_add(usage.cached_input);
        counters.reasoning_output_tokens = counters
            .reasoning_output_tokens
            .saturating_add(usage.reasoning_output);
    }
    scan.sessions = sessions.len().try_into().unwrap_or(u64::MAX);
    scan.last_observed_at_ms = observed_files.values().copied().flatten().max();
    available_agent(
        "codex",
        "Codex",
        counters,
        scan,
        SupportedDimensions {
            cache_read: false,
            cached_input: true,
            cache_creation: false,
            reasoning_output: true,
        },
    )
}

fn claude_session_key(root: &Path, path: &Path) -> PathBuf {
    let relative = path.strip_prefix(root).unwrap_or(path);
    if relative
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        == Some("subagents")
    {
        return relative
            .parent()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .unwrap_or_else(|| relative.with_extension(""));
    }
    relative.with_extension("")
}

fn claude_usage(value: ClaudeLine) -> Option<(String, ClaudeUsage)> {
    if value.kind.as_deref() != Some("assistant") {
        return None;
    }
    let message = value.message?;
    let id = message.id?;
    if id.is_empty() {
        return None;
    }
    let usage = message.usage?;
    Some((
        id,
        ClaudeUsage {
            input: usage.input_tokens.unwrap_or(0),
            output: usage.output_tokens.unwrap_or(0),
            cache_read: usage.cache_read_input_tokens.unwrap_or(0),
            cache_creation: usage.cache_creation_input_tokens.unwrap_or(0),
        },
    ))
}

fn codex_session_id(value: &CodexLine) -> Option<String> {
    if value.kind.as_deref() != Some("session_meta") {
        return None;
    }
    let id = value.payload.as_ref()?.id.as_deref()?;
    (!id.is_empty()).then(|| id.to_owned())
}

/// Split one Codex file's budget between recent cumulative snapshots and, only
/// for a tail scan, a small prefix containing `session_meta`. Prefix I/O is part
/// of the same per-file/per-source cap rather than an unaccounted extra read.
fn codex_file_budgets(file_len: u64, remaining: u64) -> (u64, u64) {
    let total = file_len.min(MAX_BYTES_PER_FILE).min(remaining);
    if file_len <= total {
        return (0, total);
    }
    let prefix = MAX_CODEX_SESSION_PREFIX_BYTES.min(total / 8);
    (prefix, total.saturating_sub(prefix))
}

fn codex_session_id_from_prefix(path: &Path, allowance: u64) -> Option<String> {
    let file = open_source_file(path).ok()?;
    let mut reader = BufReader::new(file.take(allowance));
    let mut line = Vec::new();
    for _ in 0..8 {
        match read_bounded_line(&mut reader, &mut line).ok()? {
            None => break,
            Some(true) => continue,
            Some(false) => {
                if let Ok(value) = serde_json::from_slice::<CodexLine>(&line) {
                    if let Some(id) = codex_session_id(&value) {
                        return Some(id);
                    }
                }
            }
        }
    }
    None
}

fn codex_usage(value: &CodexLine) -> Option<CodexUsage> {
    if value.kind.as_deref() != Some("event_msg") {
        return None;
    }
    let payload = value.payload.as_ref()?;
    if payload.kind.as_deref() != Some("token_count") {
        return None;
    }
    let usage = payload.info.as_ref()?.total_token_usage.as_ref()?;
    let input = usage.input_tokens.unwrap_or(0);
    let output = usage.output_tokens.unwrap_or(0);
    let total = usage
        .total_tokens
        .unwrap_or_else(|| input.saturating_add(output));
    Some(CodexUsage {
        input,
        output,
        cached_input: usage.cached_input_tokens.unwrap_or(0),
        reasoning_output: usage.reasoning_output_tokens.unwrap_or(0),
        total,
    })
}

fn agent_counters(agent: &AgentTokenUsage) -> Option<TokenCounters> {
    Some(TokenCounters {
        total_tokens: agent.total_tokens?,
        input_tokens: agent.input_tokens?,
        output_tokens: agent.output_tokens?,
        cache_read_input_tokens: agent.cache_read_input_tokens.unwrap_or(0),
        cached_input_tokens: agent.cached_input_tokens.unwrap_or(0),
        cache_creation_input_tokens: agent.cache_creation_input_tokens.unwrap_or(0),
        reasoning_output_tokens: agent.reasoning_output_tokens.unwrap_or(0),
    })
}

#[derive(Clone, Copy)]
struct SupportedDimensions {
    cache_read: bool,
    cached_input: bool,
    cache_creation: bool,
    reasoning_output: bool,
}

fn available_agent(
    agent_id: &'static str,
    display_name: &'static str,
    counters: TokenCounters,
    scan: ScanSummary,
    supported: SupportedDimensions,
) -> AgentTokenUsage {
    AgentTokenUsage {
        agent_id,
        display_name,
        availability: AgentAvailability::Available,
        total_tokens: Some(counters.total_tokens),
        input_tokens: Some(counters.input_tokens),
        output_tokens: Some(counters.output_tokens),
        cache_read_input_tokens: supported
            .cache_read
            .then_some(counters.cache_read_input_tokens),
        cached_input_tokens: supported
            .cached_input
            .then_some(counters.cached_input_tokens),
        cache_creation_input_tokens: supported
            .cache_creation
            .then_some(counters.cache_creation_input_tokens),
        reasoning_output_tokens: supported
            .reasoning_output
            .then_some(counters.reasoning_output_tokens),
        sessions: Some(scan.sessions),
        last_observed_at_ms: scan.last_observed_at_ms,
        provenance: TokenProvenance {
            source: "local_session_log",
            quality: "partial",
            note: RETAINED_HISTORY_NOTE,
        },
    }
}

fn no_data_agent(
    agent_id: &'static str,
    display_name: &'static str,
    failed: bool,
    scanned_empty: bool,
) -> AgentTokenUsage {
    AgentTokenUsage {
        agent_id,
        display_name,
        availability: if failed {
            AgentAvailability::Error
        } else {
            AgentAvailability::NoData
        },
        total_tokens: None,
        input_tokens: None,
        output_tokens: None,
        cache_read_input_tokens: None,
        cached_input_tokens: None,
        cache_creation_input_tokens: None,
        reasoning_output_tokens: None,
        sessions: scanned_empty.then_some(0),
        last_observed_at_ms: None,
        provenance: TokenProvenance {
            source: "local_session_log",
            quality: if failed { "error" } else { "no_data" },
            note: if failed { ERROR_NOTE } else { NO_DATA_NOTE },
        },
    }
}

#[cfg(windows)]
fn metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

/// Reject source components that are symlinks or Windows reparse points at
/// discovery time. Final files are also opened with no-follow semantics. As with
/// other same-user local history
/// readers, an actively malicious namespace race is outside this visibility
/// feature's trust boundary; only numeric counters ever leave the collector.
fn safe_source_root(home: &Path, components: &[&str]) -> Option<PathBuf> {
    let mut root = home.to_path_buf();
    for component in components {
        root.push(component);
        let metadata = fs::symlink_metadata(&root).ok()?;
        if metadata.file_type().is_symlink()
            || metadata_is_reparse_point(&metadata)
            || !metadata.is_dir()
        {
            return None;
        }
    }
    Some(root)
}

fn discover_jsonl(roots: &[PathBuf]) -> Discovery {
    let mut result = Discovery::default();
    let mut stack = roots.to_vec();
    let mut directories = 0usize;
    let mut entries_seen = 0usize;

    while let Some(directory) = stack.pop() {
        if directories >= MAX_DIRECTORIES_PER_SOURCE || entries_seen >= MAX_ENTRIES_PER_SOURCE {
            result.truncated = true;
            break;
        }
        directories += 1;
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(_) => {
                result.had_error = true;
                continue;
            }
        };
        for entry in entries {
            if entries_seen >= MAX_ENTRIES_PER_SOURCE {
                result.truncated = true;
                break;
            }
            entries_seen += 1;
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    result.had_error = true;
                    continue;
                }
            };
            let metadata = match entry.path().symlink_metadata() {
                Ok(metadata) => metadata,
                Err(_) => {
                    result.had_error = true;
                    continue;
                }
            };
            if metadata.file_type().is_symlink() || metadata_is_reparse_point(&metadata) {
                continue;
            }
            if metadata.is_dir() {
                stack.push(entry.path());
            } else if metadata.is_file()
                && entry
                    .path()
                    .extension()
                    .and_then(|extension| extension.to_str())
                    == Some("jsonl")
            {
                result.files.push(Candidate {
                    path: entry.path(),
                    len: metadata.len(),
                    modified_ms: metadata.modified().ok().and_then(epoch_ms),
                });
            }
        }
    }

    result.files.sort_unstable_by(|a, b| {
        b.modified_ms
            .cmp(&a.modified_ms)
            .then_with(|| a.path.cmp(&b.path))
    });
    if result.files.len() > MAX_FILES_PER_SOURCE {
        result.files.truncate(MAX_FILES_PER_SOURCE);
        result.truncated = true;
    }
    result
}

fn for_each_json_line<T: DeserializeOwned>(
    mut file: File,
    file_len: u64,
    allowance: u64,
    mut visit: impl FnMut(T),
) -> (bool, bool) {
    let start = file_len.saturating_sub(allowance);
    let discard_partial = if start > 0 {
        if file.seek(SeekFrom::Start(start - 1)).is_err() {
            return (true, true);
        }
        let mut previous = [0u8; 1];
        if file.read_exact(&mut previous).is_err() || file.seek(SeekFrom::Start(start)).is_err() {
            return (true, true);
        }
        previous[0] != b'\n'
    } else {
        false
    };
    let mut reader = BufReader::new(file.take(allowance));
    let mut line = Vec::new();
    let mut had_error = false;
    let mut truncated = start > 0;

    // A tail scan normally starts in the middle of a JSONL record. Discard only
    // that partial record; every complete recent record remains visible.
    if discard_partial {
        match read_bounded_line(&mut reader, &mut line) {
            Ok(Some(oversized)) => truncated |= oversized,
            Ok(None) => return (false, true),
            Err(_) => return (true, true),
        }
    }

    loop {
        match read_bounded_line(&mut reader, &mut line) {
            Ok(None) => break,
            Ok(Some(true)) => {
                truncated = true;
                continue;
            }
            Ok(Some(false)) => match serde_json::from_slice::<T>(&line) {
                Ok(value) => visit(value),
                Err(_) => had_error = true,
            },
            Err(_) => {
                had_error = true;
                break;
            }
        }
    }
    (had_error, truncated)
}

/// Read one JSONL record without ever allocating more than the line cap. The
/// boolean is true when an oversized record was drained and should be skipped.
fn read_bounded_line(
    reader: &mut impl BufRead,
    line: &mut Vec<u8>,
) -> std::io::Result<Option<bool>> {
    line.clear();
    let read = {
        let mut limited = reader.take((MAX_BYTES_PER_LINE + 1) as u64);
        limited.read_until(b'\n', line)?
    };
    if read == 0 {
        return Ok(None);
    }
    if line.len() <= MAX_BYTES_PER_LINE {
        return Ok(Some(false));
    }

    // The cap was reached before a newline. Drain the remainder in-place via
    // `fill_buf`/`consume`, so a malicious or corrupt giant line cannot force an
    // equally giant allocation.
    while !line.ends_with(b"\n") {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            break;
        }
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(buffer.len(), |index| index + 1);
        let saw_newline = newline.is_some();
        reader.consume(consumed);
        if saw_newline {
            break;
        }
    }
    Ok(Some(true))
}

fn open_source_file(path: &Path) -> std::io::Result<File> {
    // One shared implementation. This was the third hand copy of a
    // symlink-safe open in this workspace, and a fourth had already drifted.
    let file = innerwarden_safe_io::open_no_follow(path)?;
    let metadata = file.metadata()?;
    let unsafe_type = !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata_is_reparse_point(&metadata);
    if unsafe_type {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "token history path is not a regular file",
        ));
    }
    Ok(file)
}

fn epoch_ms(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| duration.as_millis().try_into().ok())
}

fn max_option(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn agent<'a>(report: &'a TokenIntelligence, id: &str) -> &'a AgentTokenUsage {
        report
            .agents
            .iter()
            .find(|agent| agent.agent_id == id)
            .unwrap()
    }

    #[test]
    fn claude_deduplicates_message_ids_using_one_observed_snapshot() {
        let home = tempfile::tempdir().unwrap();
        let project_a = home.path().join(".claude/projects/a");
        let project_b = home.path().join(".claude/projects/b");
        fs::create_dir_all(&project_a).unwrap();
        fs::create_dir_all(&project_b).unwrap();
        fs::write(
            project_a.join("one.jsonl"),
            concat!(
                r#"{"type":"assistant","message":{"id":"same","usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":3,"cache_creation_input_tokens":1}}}"#,
                "\n",
                r#"{"type":"assistant","message":{"id":"other","usage":{"input_tokens":2,"output_tokens":1}}}"#,
                "\n"
            ),
        )
        .unwrap();
        fs::write(
            project_b.join("two.jsonl"),
            concat!(
                r#"{"type":"assistant","message":{"id":"same","usage":{"input_tokens":8,"output_tokens":7,"cache_read_input_tokens":2,"cache_creation_input_tokens":4}}}"#,
                "\n"
            ),
        )
        .unwrap();

        let report = collect(home.path());
        let claude = agent(&report, "claude");
        assert_eq!(claude.availability, AgentAvailability::Available);
        assert_eq!(claude.total_tokens, Some(24));
        assert_eq!(claude.input_tokens, Some(10));
        assert_eq!(claude.output_tokens, Some(8));
        assert_eq!(claude.cache_read_input_tokens, Some(2));
        assert_eq!(claude.cached_input_tokens, None);
        assert_eq!(claude.cache_creation_input_tokens, Some(4));
        assert_eq!(claude.reasoning_output_tokens, None);
        assert_eq!(claude.sessions, Some(2));
        assert!(claude.last_observed_at_ms.is_some());
    }

    #[test]
    fn claude_subagent_history_counts_as_its_parent_session() {
        let home = tempfile::tempdir().unwrap();
        let project = home.path().join(".claude/projects/project");
        let subagents = project.join("session-one/subagents");
        fs::create_dir_all(&subagents).unwrap();
        fs::write(
            project.join("session-one.jsonl"),
            r#"{"type":"assistant","message":{"id":"main","usage":{"input_tokens":2,"output_tokens":1}}}"#,
        )
        .unwrap();
        fs::write(
            subagents.join("agent-worker.jsonl"),
            r#"{"type":"assistant","message":{"id":"worker","usage":{"input_tokens":3,"output_tokens":1}}}"#,
        )
        .unwrap();

        let report = collect(home.path());
        let claude = agent(&report, "claude");
        assert_eq!(claude.sessions, Some(1));
        assert_eq!(claude.total_tokens, Some(7));
    }

    #[test]
    fn codex_uses_one_cumulative_max_per_session_without_double_counting_subsets() {
        let home = tempfile::tempdir().unwrap();
        let sessions = home.path().join(".codex/sessions/2026/07");
        let archived = home.path().join(".codex/archived_sessions");
        fs::create_dir_all(&sessions).unwrap();
        fs::create_dir_all(&archived).unwrap();
        fs::write(
            sessions.join("a.jsonl"),
            concat!(
                r#"{"type":"session_meta","payload":{"id":"session-a"}}"#,
                "\n",
                r#"{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":80,"cached_input_tokens":30,"output_tokens":15,"reasoning_output_tokens":4,"total_tokens":95}}}}"#,
                "\n",
                r#"{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":100,"cached_input_tokens":40,"output_tokens":20,"reasoning_output_tokens":5,"total_tokens":120}}}}"#,
                "\n"
            ),
        )
        .unwrap();
        fs::write(
            archived.join("a-copy.jsonl"),
            concat!(
                r#"{"type":"session_meta","payload":{"id":"session-a"}}"#,
                "\n",
                r#"{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":90,"cached_input_tokens":35,"output_tokens":18,"reasoning_output_tokens":4,"total_tokens":108}}}}"#,
                "\n"
            ),
        )
        .unwrap();
        fs::write(
            sessions.join("b.jsonl"),
            concat!(
                r#"{"type":"session_meta","payload":{"id":"session-b"}}"#,
                "\n",
                r#"{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":5,"cached_input_tokens":2,"output_tokens":3,"reasoning_output_tokens":1,"total_tokens":8}}}}"#,
                "\n"
            ),
        )
        .unwrap();

        let report = collect(home.path());
        let codex = agent(&report, "codex");
        assert_eq!(codex.total_tokens, Some(128));
        assert_eq!(codex.input_tokens, Some(105));
        assert_eq!(codex.output_tokens, Some(23));
        assert_eq!(codex.cached_input_tokens, Some(42));
        assert_eq!(codex.cache_read_input_tokens, None);
        assert_eq!(codex.cache_creation_input_tokens, None);
        assert_eq!(codex.reasoning_output_tokens, Some(6));
        assert_eq!(codex.sessions, Some(2));
        // Cached and reasoning counters are subsets: 128, not 176.
        assert_ne!(codex.total_tokens, Some(128 + 42 + 6));
    }

    #[test]
    fn codex_prefix_scan_is_charged_to_the_shared_source_budget() {
        let oversized = MAX_BYTES_PER_FILE.saturating_mul(2);
        let mut remaining = MAX_BYTES_PER_SOURCE;
        let mut spent = 0;
        for _ in 0..MAX_FILES_PER_SOURCE {
            let (prefix, tail) = codex_file_budgets(oversized, remaining);
            assert!(prefix <= MAX_CODEX_SESSION_PREFIX_BYTES);
            assert!(prefix.saturating_add(tail) <= MAX_BYTES_PER_FILE);
            let file_spend = prefix.saturating_add(tail);
            remaining = remaining.saturating_sub(file_spend);
            spent += file_spend;
            if remaining == 0 {
                break;
            }
        }
        assert_eq!(spent, MAX_BYTES_PER_SOURCE);
        assert_eq!(remaining, 0);
    }

    #[test]
    fn unavailable_is_null_while_observed_zero_is_zero() {
        let home = tempfile::tempdir().unwrap();
        fs::create_dir_all(home.path().join(".claude/projects/empty")).unwrap();
        fs::create_dir_all(home.path().join(".codex/sessions/empty")).unwrap();

        let report = collect(home.path());
        assert_eq!(report.availability, ReportAvailability::NoData);
        assert_eq!(report.totals, None);
        let claude = agent(&report, "claude");
        assert_eq!(claude.availability, AgentAvailability::NoData);
        assert_eq!(claude.total_tokens, None);
        assert_eq!(claude.sessions, Some(0));
        assert_eq!(claude.provenance.quality, "no_data");
        assert_eq!(claude.provenance.note, NO_DATA_NOTE);
        let cursor = agent(&report, "cursor");
        assert_eq!(cursor.availability, AgentAvailability::Unsupported);
        assert_eq!(cursor.total_tokens, None);
        assert_eq!(cursor.sessions, None);

        let missing_home = tempfile::tempdir().unwrap();
        let missing = collect(missing_home.path());
        assert_eq!(agent(&missing, "claude").sessions, None);
        assert_eq!(agent(&missing, "codex").sessions, None);
    }

    #[test]
    fn initial_background_snapshot_is_explicitly_loading_and_private() {
        let report = loading_report();
        assert_eq!(report.availability, ReportAvailability::Loading);
        assert_eq!(
            agent(&report, "claude").availability,
            AgentAvailability::Loading
        );
        assert_eq!(agent(&report, "claude").total_tokens, None);
        assert_eq!(
            agent(&report, "cursor").availability,
            AgentAvailability::Unsupported
        );
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(serialized.contains("\"availability\":\"loading\""));
        assert!(!serialized.contains("session_id"));
    }

    #[test]
    fn unreadable_or_malformed_history_is_reported_as_error_not_no_data() {
        let home = tempfile::tempdir().unwrap();
        let project = home.path().join(".claude/projects/broken");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("broken.jsonl"), "not-json\n").unwrap();

        let report = collect(home.path());
        assert_eq!(report.availability, ReportAvailability::Error);
        let claude = agent(&report, "claude");
        assert_eq!(claude.availability, AgentAvailability::Error);
        assert_eq!(claude.provenance.quality, "error");
        assert_eq!(claude.provenance.note, ERROR_NOTE);
    }

    #[test]
    fn arithmetic_saturates_instead_of_wrapping() {
        let home = tempfile::tempdir().unwrap();
        let project = home.path().join(".claude/projects/large");
        fs::create_dir_all(&project).unwrap();
        fs::write(
            project.join("large.jsonl"),
            concat!(
                r#"{"type":"assistant","message":{"id":"first","usage":{"input_tokens":18446744073709551615,"output_tokens":1}}}"#,
                "\n",
                r#"{"type":"assistant","message":{"id":"second","usage":{"input_tokens":1,"output_tokens":18446744073709551615}}}"#,
                "\n"
            ),
        )
        .unwrap();

        let report = collect(home.path());
        let claude = agent(&report, "claude");
        assert_eq!(claude.total_tokens, Some(u64::MAX));
        assert_eq!(claude.input_tokens, Some(u64::MAX));
        assert_eq!(claude.output_tokens, Some(u64::MAX));
        assert_eq!(report.totals.as_ref().unwrap().total_tokens, u64::MAX);
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(serialized.contains(&format!("\"{}\"", u64::MAX)));
    }

    #[test]
    fn report_serialization_contains_no_private_source_fields_or_values() {
        let home = tempfile::tempdir().unwrap();
        let project = home.path().join(".claude/projects/private");
        fs::create_dir_all(&project).unwrap();
        fs::write(
            project.join("private.jsonl"),
            concat!(
                r#"{"type":"assistant","session_id":"secret-session-381","pid":"private-process-99881","cwd":"/secret/customer/path","email":"person@example.test","message":{"id":"secret-message-772","content":"rm -rf private-code","usage":{"input_tokens":0,"output_tokens":0}}}"#,
                "\n"
            ),
        )
        .unwrap();

        let serialized = serde_json::to_string(&collect(home.path())).unwrap();
        for secret in [
            "secret-session-381",
            "secret-message-772",
            "/secret/customer/path",
            "person@example.test",
            "rm -rf private-code",
            "private-process-99881",
        ] {
            assert!(
                !serialized.contains(secret),
                "leaked private value: {secret}"
            );
        }
        for forbidden_key in [
            "session_id",
            "message_id",
            "path",
            "email",
            "pid",
            "content",
        ] {
            assert!(!serialized.contains(&format!("\"{forbidden_key}\"")));
        }
        assert!(serialized.contains("\"total_tokens\":\"0\""));
        assert!(serialized.contains("\"cached_input_tokens\":null"));
        assert!(serialized.contains("not a billing statement"));
    }

    #[test]
    fn truncated_files_are_scanned_from_the_recent_tail() {
        let old = concat!(
            r#"{"type":"assistant","message":{"id":"old","usage":{"input_tokens":1}}}"#,
            "\n"
        );
        let middle = concat!(
            r#"{"type":"assistant","message":{"id":"middle","usage":{"input_tokens":2}}}"#,
            "\n"
        );
        let recent = concat!(
            r#"{"type":"assistant","message":{"id":"recent","usage":{"input_tokens":9}}}"#,
            "\n"
        );
        let body = format!("{old}{middle}{recent}");
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), body.as_bytes()).unwrap();
        let allowance = (middle.len() / 2 + recent.len()) as u64;
        let mut ids = Vec::new();
        let (error, truncated) = for_each_json_line::<ClaudeLine>(
            open_source_file(file.path()).unwrap(),
            body.len() as u64,
            allowance,
            |line| {
                if let Some(message) = line.message {
                    if let Some(id) = message.id {
                        ids.push(id);
                    }
                }
            },
        );
        assert!(!error);
        assert!(truncated);
        assert_eq!(ids, vec!["recent"]);
    }

    #[test]
    fn oversized_jsonl_record_is_drained_with_bounded_memory() {
        let mut body = vec![b'x'; MAX_BYTES_PER_LINE + 100];
        body.push(b'\n');
        body.extend_from_slice(b"{}\n");
        let mut reader = BufReader::new(std::io::Cursor::new(body));
        let mut line = Vec::new();
        assert_eq!(
            read_bounded_line(&mut reader, &mut line).unwrap(),
            Some(true)
        );
        assert!(line.len() <= MAX_BYTES_PER_LINE + 1);
        assert_eq!(
            read_bounded_line(&mut reader, &mut line).unwrap(),
            Some(false)
        );
        assert_eq!(line, b"{}\n");
    }

    #[cfg(unix)]
    #[test]
    fn does_not_follow_source_or_file_symlinks() {
        use std::os::unix::fs::symlink;

        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir_all(home.path().join(".claude")).unwrap();
        fs::create_dir_all(outside.path().join("projects")).unwrap();
        fs::write(
            outside.path().join("projects/outside.jsonl"),
            r#"{"type":"assistant","message":{"id":"outside","usage":{"input_tokens":999}}}"#,
        )
        .unwrap();
        symlink(
            outside.path().join("projects"),
            home.path().join(".claude/projects"),
        )
        .unwrap();

        let report = collect(home.path());
        assert_eq!(agent(&report, "claude").total_tokens, None);

        fs::remove_file(home.path().join(".claude/projects")).unwrap();
        fs::create_dir(home.path().join(".claude/projects")).unwrap();
        symlink(
            outside.path().join("projects/outside.jsonl"),
            home.path().join(".claude/projects/link.jsonl"),
        )
        .unwrap();
        let report = collect(home.path());
        assert_eq!(agent(&report, "claude").total_tokens, None);
    }

    #[cfg(unix)]
    #[test]
    fn source_open_rejects_a_fifo_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let home = tempfile::tempdir().unwrap();
        let fifo_path = home.path().join("history.jsonl");
        let fifo = CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

        let error = open_source_file(&fifo_path).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
}
