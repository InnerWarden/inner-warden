//! Privacy-preserving token intelligence from retained local agent history.
//!
//! The collector intentionally reads only numeric usage counters from the
//! supported retained local history roots below. It never returns session/message IDs,
//! prompts, code, file paths, account data, process data, or parser errors.
//! Local history is incomplete by nature, so these values are observability
//! counters rather than a billing statement.
//!
//! The whole retained history is counted, not its newest tail. A long-lived
//! [`TokenScanner`] keeps a small per-file index (length, time, how far the
//! file was read) and reads only the bytes appended since the last pass; a
//! file that shrank, was rewritten or removed is dropped and the index is
//! rebuilt. Message and session identifiers are used only to deduplicate, as
//! 64-bit digests held in memory, and never leave the process. When a cap
//! still cuts the scan, every affected row carries a [`TokenCoverage`] saying
//! so, and its figures are a sample of the newest history, not the total.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_FILES_PER_SOURCE: usize = 16_384;
const MAX_DIRECTORIES_PER_SOURCE: usize = 32_768;
const MAX_ENTRIES_PER_SOURCE: usize = 500_000;
/// New bytes read per pass and per source. A larger history is caught up over
/// several passes, newest files first; this bounds the cost of one refresh.
const MAX_BYTES_PER_PASS: u64 = 1024 * 1024 * 1024;
const MAX_BYTES_PER_LINE: usize = 2 * 1024 * 1024;
/// Distinct messages (or sessions) held for deduplication, about 100 MB.
const MAX_USAGE_RECORDS_PER_SOURCE: usize = 2_000_000;
/// Pause between passes while a large history is still being caught up.
const CATCH_UP_PAUSE: Duration = Duration::from_secs(1);

const RETAINED_HISTORY_NOTE: &str =
    "Provider-reported counters found in retained local history; partial and not a billing statement.";
const SAMPLE_NOTE: &str =
    "A sample of the newest retained local history, not the total; partial and not a billing statement.";
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
    /// How much of the retained history the figures cover; absent for a row
    /// with no counters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage: Option<TokenCoverage>,
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
    /// History files found before the file cap cut the list.
    found: usize,
    had_error: bool,
    truncated: bool,
}

#[derive(Debug, Default)]
struct ScanSummary {
    sessions: u64,
    last_observed_at_ms: Option<u64>,
    had_error: bool,
    truncated: bool,
    coverage: Option<TokenCoverage>,
}

/// Caps on one scan of one provider's history.
///
/// The caps bound memory and the work done per pass, not how much history is
/// counted: a pass reads at most `bytes_per_pass` of new bytes, newest files
/// first, and the next pass carries on from where it stopped. Only a cap that
/// can never be caught up (files, entries, records) leaves the figures as a
/// sample, and the report says so.
#[derive(Debug, Clone, Copy)]
struct ScanLimits {
    files: usize,
    directories: usize,
    entries: usize,
    bytes_per_pass: u64,
    records: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            files: MAX_FILES_PER_SOURCE,
            directories: MAX_DIRECTORIES_PER_SOURCE,
            entries: MAX_ENTRIES_PER_SOURCE,
            bytes_per_pass: MAX_BYTES_PER_PASS,
            records: MAX_USAGE_RECORDS_PER_SOURCE,
        }
    }
}

/// How much of the retained history one agent's figures cover. Numbers only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TokenCoverage {
    /// False when a cap cut the scan: the figures are then a sample of the
    /// newest history and must not be read as the total.
    pub complete: bool,
    /// History files whose content is counted.
    pub files_read: u64,
    /// History files found on this machine.
    pub files_found: u64,
}

/// A 64-bit digest of an identifier. The index keeps these instead of the
/// identifiers themselves, so no message or session id is held in memory.
fn digest64(bytes: &[u8]) -> u64 {
    let digest = Sha256::digest(bytes);
    let mut head = [0u8; 8];
    head.copy_from_slice(&digest.as_slice()[..8]);
    u64::from_be_bytes(head)
}

/// The bytes before a resume point that are checked to still be what was read.
const ANCHOR_BYTES: u64 = 32;

/// A digest of the few bytes that end at `offset`, or `None` if they cannot be
/// read. A history file that is rewritten in place, rather than appended to,
/// no longer matches the digest taken when it was read.
fn read_anchor(file: &mut File, offset: u64) -> Option<u64> {
    let length = ANCHOR_BYTES.min(offset);
    let mut buffer = [0u8; ANCHOR_BYTES as usize];
    file.seek(SeekFrom::Start(offset - length)).ok()?;
    file.read_exact(&mut buffer[..length as usize]).ok()?;
    Some(digest64(&buffer[..length as usize]))
}

/// What differs between providers in the incremental index.
trait Provider {
    type Line: DeserializeOwned;
    /// What one file contributes on its own.
    type File: Default;
    /// What is deduplicated across files.
    type Global: Default;

    /// Fold one record in. True when the record cap dropped something.
    fn apply(
        global: &mut Self::Global,
        file: &mut Self::File,
        line: Self::Line,
        records: usize,
    ) -> bool;

    /// Called after a file has been read as far as it goes in this pass.
    fn finish(_global: &mut Self::Global, _file: &Self::File, _records: usize) -> bool {
        false
    }
}

/// Where the last pass stopped in one history file.
#[derive(Debug, Default)]
struct Tracked<F> {
    len: u64,
    modified_ms: Option<u64>,
    /// Offset just past the last record counted.
    offset: u64,
    anchor: u64,
    /// The last pass ran out of byte budget inside this file.
    cut: bool,
    parse_error: bool,
    skipped_oversized: bool,
    state: F,
}

#[derive(Debug, Default)]
struct PassOutcome {
    files_found: usize,
    files_read: usize,
    budget_cut: bool,
    discovery_truncated: bool,
    had_error: bool,
}

/// An incremental index of one provider's history files.
///
/// History is append-only, so a file that grew is read from where the last
/// pass stopped and a file that did not change is not opened. Anything else
/// (a file that shrank, whose time moved back, whose already-read bytes
/// changed, or that was removed) cannot be undone from the totals, so the
/// index is dropped and rebuilt, which costs one full read of the history.
struct Index<P: Provider> {
    files: HashMap<PathBuf, Tracked<P::File>>,
    global: P::Global,
    /// A record was dropped because the record cap was full.
    records_capped: bool,
}

impl<P: Provider> Index<P> {
    fn new() -> Self {
        Self {
            files: HashMap::new(),
            global: P::Global::default(),
            records_capped: false,
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    fn any_skipped_oversized(&self) -> bool {
        self.files.values().any(|tracked| tracked.skipped_oversized)
    }

    fn any_parse_error(&self) -> bool {
        self.files.values().any(|tracked| tracked.parse_error)
    }

    fn needs_rebuild(&self, discovery: &Discovery) -> bool {
        let present: HashMap<&Path, &Candidate> = discovery
            .files
            .iter()
            .map(|candidate| (candidate.path.as_path(), candidate))
            .collect();
        self.files
            .iter()
            .any(|(path, tracked)| match present.get(path.as_path()) {
                // A cap-limited listing proves nothing about absence.
                None => !discovery.truncated,
                Some(candidate) => {
                    candidate.len < tracked.len
                        || matches!(
                            (candidate.modified_ms, tracked.modified_ms),
                            (Some(now), Some(before)) if now < before
                        )
                }
            })
    }

    fn scan(&mut self, roots: &[PathBuf], limits: &ScanLimits) -> PassOutcome {
        let discovery = discover_jsonl(roots, limits);
        if self.needs_rebuild(&discovery) {
            self.reset();
        }
        for _ in 0..2 {
            if let Some(outcome) = self.read_pass(&discovery, limits) {
                return outcome;
            }
            // Bytes already counted changed under us.
            self.reset();
        }
        PassOutcome {
            had_error: true,
            ..PassOutcome::default()
        }
    }

    /// One pass over the discovered files. `None` means a file's already-read
    /// bytes no longer match, and the caller must rebuild from scratch.
    fn read_pass(&mut self, discovery: &Discovery, limits: &ScanLimits) -> Option<PassOutcome> {
        let Self {
            files,
            global,
            records_capped,
        } = self;
        let mut remaining = limits.bytes_per_pass;
        let mut outcome = PassOutcome {
            files_found: discovery.found,
            discovery_truncated: discovery.truncated,
            had_error: discovery.had_error,
            ..PassOutcome::default()
        };

        for candidate in &discovery.files {
            let known = files.get(&candidate.path);
            if known.is_some_and(|tracked| {
                !tracked.cut
                    && tracked.len == candidate.len
                    && tracked.modified_ms == candidate.modified_ms
            }) {
                outcome.files_read += 1;
                continue;
            }
            let start = known.map_or(0, |tracked| tracked.offset);
            let wanted = candidate.len.saturating_sub(start);
            if wanted == 0 {
                let tracked = files.entry(candidate.path.clone()).or_default();
                tracked.len = candidate.len;
                tracked.modified_ms = candidate.modified_ms;
                tracked.cut = false;
                outcome.files_read += 1;
                continue;
            }
            if remaining == 0 {
                outcome.budget_cut = true;
                if let Some(tracked) = files.get_mut(&candidate.path) {
                    tracked.cut = true;
                }
                continue;
            }
            let Ok(mut file) = open_source_file(&candidate.path) else {
                outcome.had_error = true;
                continue;
            };
            if let Some(tracked) = known {
                if tracked.offset > 0
                    && read_anchor(&mut file, tracked.offset) != Some(tracked.anchor)
                {
                    return None;
                }
            }
            let stop = start + wanted.min(remaining);
            remaining -= stop - start;

            let tracked = files.entry(candidate.path.clone()).or_default();
            let range = for_each_json_line::<P::Line>(&mut file, start, stop, |line| {
                if P::apply(global, &mut tracked.state, line, limits.records) {
                    *records_capped = true;
                }
            });
            if P::finish(global, &tracked.state, limits.records) {
                *records_capped = true;
            }
            tracked.len = candidate.len;
            tracked.modified_ms = candidate.modified_ms;
            tracked.offset = range.end;
            tracked.anchor = read_anchor(&mut file, range.end).unwrap_or(0);
            tracked.parse_error |= range.had_error;
            tracked.skipped_oversized |= range.skipped_oversized;
            tracked.cut = stop < candidate.len;
            if tracked.cut {
                outcome.budget_cut = true;
            } else {
                outcome.files_read += 1;
            }
        }
        Some(outcome)
    }

    /// The scan summary every provider shares.
    fn summary(&self, pass: &PassOutcome) -> ScanSummary {
        let incomplete = pass.budget_cut
            || pass.discovery_truncated
            || self.records_capped
            || self.any_skipped_oversized();
        ScanSummary {
            sessions: 0,
            last_observed_at_ms: None,
            had_error: pass.had_error || self.any_parse_error(),
            truncated: incomplete,
            coverage: Some(TokenCoverage {
                complete: !incomplete,
                files_read: pass.files_read.try_into().unwrap_or(u64::MAX),
                files_found: pass.files_found.try_into().unwrap_or(u64::MAX),
            }),
        }
    }
}

#[derive(Debug, Default)]
struct ClaudeFile {
    saw_usage: bool,
}

struct ClaudeProvider;

impl Provider for ClaudeProvider {
    type Line = ClaudeLine;
    type File = ClaudeFile;
    type Global = HashMap<u64, ClaudeUsage>;

    fn apply(
        global: &mut Self::Global,
        file: &mut Self::File,
        line: ClaudeLine,
        records: usize,
    ) -> bool {
        let Some((message_id, usage)) = claude_usage(line) else {
            return false;
        };
        file.saw_usage = true;
        let key = digest64(message_id.as_bytes());
        if let Some(existing) = global.get_mut(&key) {
            existing.keep_larger_snapshot(&usage);
            false
        } else if global.len() < records {
            global.insert(key, usage);
            false
        } else {
            true
        }
    }
}

#[derive(Debug, Default)]
struct CodexFile {
    session: Option<u64>,
    cumulative: CodexUsage,
    saw_usage: bool,
}

struct CodexProvider;

impl Provider for CodexProvider {
    type Line = CodexLine;
    type File = CodexFile;
    type Global = HashMap<u64, CodexUsage>;

    fn apply(
        _global: &mut Self::Global,
        file: &mut Self::File,
        line: CodexLine,
        _records: usize,
    ) -> bool {
        if file.session.is_none() {
            file.session = codex_session_id(&line).map(|id| digest64(id.as_bytes()));
        }
        if let Some(usage) = codex_usage(&line) {
            file.saw_usage = true;
            file.cumulative.keep_larger_snapshot(&usage);
        }
        false
    }

    fn finish(global: &mut Self::Global, file: &Self::File, records: usize) -> bool {
        let (true, Some(session)) = (file.saw_usage, file.session) else {
            return false;
        };
        if let Some(existing) = global.get_mut(&session) {
            existing.keep_larger_snapshot(&file.cumulative);
            false
        } else if global.len() < records {
            global.insert(session, file.cumulative.clone());
            false
        } else {
            true
        }
    }
}

/// Collects numeric token counters across refreshes, reading only what was
/// appended to the history since the last pass.
pub struct TokenScanner {
    claude: Index<ClaudeProvider>,
    codex: Index<CodexProvider>,
    limits: ScanLimits,
    catching_up: bool,
}

impl Default for TokenScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenScanner {
    pub fn new() -> Self {
        Self::with_limits(ScanLimits::default())
    }

    fn with_limits(limits: ScanLimits) -> Self {
        Self {
            claude: Index::new(),
            codex: Index::new(),
            limits,
            catching_up: false,
        }
    }

    /// True when the last pass stopped on its byte budget before reaching all
    /// the history, so another pass should follow without waiting.
    pub fn catching_up(&self) -> bool {
        self.catching_up
    }

    /// One pass over the history below `home`: the exact Claude Code and Codex
    /// local roots. Cursor is represented honestly as unsupported; no undocumented
    /// database or inferred billing data is read.
    pub fn scan(&mut self, home: &Path) -> TokenIntelligence {
        let (claude, claude_pending) = self.claude_report(home);
        let (codex, codex_pending) = self.codex_report(home);
        self.catching_up = claude_pending || codex_pending;
        let cursor = unsupported_agent("cursor", "Cursor");

        let numeric_agents = [&claude, &codex]
            .into_iter()
            .filter_map(agent_counters)
            .collect::<Vec<_>>();
        let totals = if numeric_agents.is_empty() {
            None
        } else {
            Some(numeric_agents.into_iter().fold(
                TokenCounters::default(),
                |mut total, counters| {
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
                },
            ))
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

    fn claude_report(&mut self, home: &Path) -> (AgentTokenUsage, bool) {
        let Some(root) = safe_source_root(home, &[".claude", "projects"]) else {
            self.claude.reset();
            return (no_data_agent("claude", "Claude Code", false, false), false);
        };
        let pass = self.claude.scan(std::slice::from_ref(&root), &self.limits);
        let mut scan = self.claude.summary(&pass);

        let mut sessions: HashSet<PathBuf> = HashSet::new();
        for (path, tracked) in &self.claude.files {
            if tracked.state.saw_usage {
                sessions.insert(claude_session_key(&root, path));
                scan.last_observed_at_ms =
                    max_option(scan.last_observed_at_ms, tracked.modified_ms);
            }
        }

        if self.claude.global.is_empty() {
            let failed = scan.had_error || scan.truncated;
            return (
                no_data_agent("claude", "Claude Code", failed, !failed),
                pass.budget_cut,
            );
        }

        let mut counters = TokenCounters::default();
        for usage in self.claude.global.values() {
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
        (
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
            ),
            pass.budget_cut,
        )
    }

    fn codex_report(&mut self, home: &Path) -> (AgentTokenUsage, bool) {
        let roots = [
            safe_source_root(home, &[".codex", "sessions"]),
            safe_source_root(home, &[".codex", "archived_sessions"]),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        if roots.is_empty() {
            self.codex.reset();
            return (no_data_agent("codex", "Codex", false, false), false);
        }
        let pass = self.codex.scan(&roots, &self.limits);
        let mut scan = self.codex.summary(&pass);
        for tracked in self.codex.files.values() {
            if !tracked.state.saw_usage {
                continue;
            }
            if tracked.state.session.is_some() {
                scan.last_observed_at_ms =
                    max_option(scan.last_observed_at_ms, tracked.modified_ms);
            } else {
                // Without the provider's session ID, cumulative snapshots cannot
                // be deduplicated safely, so fail closed instead of inflating use.
                scan.had_error = true;
            }
        }

        if self.codex.global.is_empty() {
            let failed = scan.had_error || scan.truncated;
            return (
                no_data_agent("codex", "Codex", failed, !failed),
                pass.budget_cut,
            );
        }

        let mut counters = TokenCounters::default();
        for usage in self.codex.global.values() {
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
        scan.sessions = self.codex.global.len().try_into().unwrap_or(u64::MAX);
        (
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
            ),
            pass.budget_cut,
        )
    }
}
/// Collect numeric token counters from the exact Claude Code and Codex local
/// history roots below `home`, with a fresh index. A long-lived caller keeps a
/// [`TokenScanner`] instead, so each refresh reads only what was appended.
pub fn collect(home: &Path) -> TokenIntelligence {
    TokenScanner::new().scan(home)
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
        .spawn(move || {
            let mut scanner = TokenScanner::new();
            loop {
                let next = scanner.scan(&home);
                match writer.write() {
                    Ok(mut report) => *report = next,
                    Err(poisoned) => *poisoned.into_inner() = next,
                }
                if scanner.catching_up() {
                    std::thread::sleep(CATCH_UP_PAUSE);
                    continue;
                }
                if refresh_every.is_zero() {
                    break;
                }
                std::thread::sleep(refresh_every);
            }
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
            coverage: None,
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
        coverage: None,
        provenance: TokenProvenance {
            source: "not_available",
            quality: "unsupported",
            note: UNSUPPORTED_NOTE,
        },
    }
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
    let sample = scan.coverage.is_some_and(|coverage| !coverage.complete);
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
            quality: if sample { "sample" } else { "partial" },
            note: if sample {
                SAMPLE_NOTE
            } else {
                RETAINED_HISTORY_NOTE
            },
        },
        coverage: scan.coverage,
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
        coverage: None,
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

fn discover_jsonl(roots: &[PathBuf], limits: &ScanLimits) -> Discovery {
    let mut result = Discovery::default();
    let mut stack = roots.to_vec();
    let mut directories = 0usize;
    let mut entries_seen = 0usize;

    while let Some(directory) = stack.pop() {
        if directories >= limits.directories || entries_seen >= limits.entries {
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
            if entries_seen >= limits.entries {
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
    // Newest first, so that when a cap cuts it is the oldest history that is
    // left out and a catch-up pass reads the most recent files before the rest.
    result.files.sort_unstable_by(|a, b| {
        b.modified_ms
            .cmp(&a.modified_ms)
            .then_with(|| a.path.cmp(&b.path))
    });
    result.found = result.files.len();
    if result.files.len() > limits.files {
        result.files.truncate(limits.files);
        result.truncated = true;
    }
    result
}

/// What one bounded read of a byte range found.
#[derive(Debug, Default, PartialEq, Eq)]
struct RangeRead {
    /// Offset just past the last record that was fully handled. A trailing
    /// record that is still being written stays after it, to be read again.
    end: u64,
    had_error: bool,
    /// A complete record over the line cap was skipped.
    skipped_oversized: bool,
}

/// Visit every complete JSONL record in `start..stop`.
///
/// `start` must be the start of a record (offset 0, or an offset this function
/// returned earlier). A final record with no newline is used only when it
/// already parses as JSON, because a record cut off by a writer in mid-line
/// cannot; otherwise it is left for the next read rather than counted as
/// malformed.
fn for_each_json_line<T: DeserializeOwned>(
    file: &mut File,
    start: u64,
    stop: u64,
    mut visit: impl FnMut(T),
) -> RangeRead {
    let mut outcome = RangeRead {
        end: start,
        ..RangeRead::default()
    };
    if stop <= start {
        return outcome;
    }
    if file.seek(SeekFrom::Start(start)).is_err() {
        outcome.had_error = true;
        return outcome;
    }
    let mut reader = BufReader::new(file.take(stop - start));
    let mut line = Vec::new();
    loop {
        match read_bounded_line(&mut reader, &mut line) {
            Ok(None) => break,
            Ok(Some(read)) => {
                if read.oversized {
                    if !read.terminated {
                        break;
                    }
                    outcome.skipped_oversized = true;
                } else if read.terminated {
                    if serde_json::from_slice::<T>(&line).map(&mut visit).is_err() {
                        outcome.had_error = true;
                    }
                } else {
                    match serde_json::from_slice::<T>(&line) {
                        Ok(value) => visit(value),
                        Err(_) => break,
                    }
                }
                outcome.end += read.bytes;
            }
            Err(_) => {
                outcome.had_error = true;
                break;
            }
        }
    }
    outcome
}

/// One record read by [`read_bounded_line`].
struct LineRead {
    /// The record was over the line cap; its bytes were drained, not kept.
    oversized: bool,
    /// The record ended with a newline (it is not a half-written tail).
    terminated: bool,
    /// Bytes the record occupied in the file, newline included.
    bytes: u64,
}

/// Read one JSONL record without ever allocating more than the line cap.
fn read_bounded_line(
    reader: &mut impl BufRead,
    line: &mut Vec<u8>,
) -> std::io::Result<Option<LineRead>> {
    line.clear();
    let read = {
        let mut limited = reader.take((MAX_BYTES_PER_LINE + 1) as u64);
        limited.read_until(b'\n', line)?
    };
    if read == 0 {
        return Ok(None);
    }
    if line.len() <= MAX_BYTES_PER_LINE {
        return Ok(Some(LineRead {
            oversized: false,
            terminated: line.ends_with(b"\n"),
            bytes: line.len() as u64,
        }));
    }

    // The cap was reached before a newline. Drain the remainder in-place via
    // `fill_buf`/`consume`, so a malicious or corrupt giant line cannot force an
    // equally giant allocation.
    let mut bytes = line.len() as u64;
    let mut terminated = line.ends_with(b"\n");
    while !terminated {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            break;
        }
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(buffer.len(), |index| index + 1);
        reader.consume(consumed);
        bytes += consumed as u64;
        if newline.is_some() {
            terminated = true;
            break;
        }
    }
    Ok(Some(LineRead {
        oversized: true,
        terminated,
        bytes,
    }))
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
        assert!(serialized
            .contains("\"coverage\":{\"complete\":true,\"files_read\":1,\"files_found\":1}"));
    }

    fn msg(id: &str, input: u64, output: u64) -> String {
        format!(
            "{{\"type\":\"assistant\",\"message\":{{\"id\":\"{id}\",\"usage\":{{\"input_tokens\":{input},\"output_tokens\":{output}}}}}}}\n"
        )
    }

    fn codex_meta(id: &str) -> String {
        format!("{{\"type\":\"session_meta\",\"payload\":{{\"id\":\"{id}\"}}}}\n")
    }

    fn codex_count(input: u64, output: u64) -> String {
        format!(
            "{{\"type\":\"event_msg\",\"payload\":{{\"type\":\"token_count\",\"info\":{{\"total_token_usage\":{{\"input_tokens\":{input},\"output_tokens\":{output},\"total_tokens\":{}}}}}}}}}\n",
            input + output
        )
    }

    fn set_mtime(path: &Path, seconds_ago: u64) {
        let file = fs::OpenOptions::new().write(true).open(path).unwrap();
        file.set_modified(SystemTime::now() - Duration::from_secs(seconds_ago))
            .unwrap();
    }

    fn append(path: &Path, text: &str) {
        use std::io::Write;
        let mut file = fs::OpenOptions::new().append(true).open(path).unwrap();
        file.write_all(text.as_bytes()).unwrap();
    }

    fn claude_dir(home: &Path) -> PathBuf {
        let dir = home.join(".claude/projects/p");
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn limits(files: usize, bytes_per_pass: u64, records: usize) -> ScanLimits {
        ScanLimits {
            files,
            bytes_per_pass,
            records,
            ..ScanLimits::default()
        }
    }

    #[test]
    fn history_larger_than_the_old_per_source_cap_is_counted_in_full() {
        // The collector used to read only the newest 64 MB per source (and 32 MB
        // per file) and presented that as the total.
        let home = tempfile::tempdir().unwrap();
        let dir = claude_dir(home.path());
        let pad = "x".repeat(1024 * 1024);
        let mut expected = 0;
        for file in 0..2 {
            let mut body = String::new();
            for n in 0..40 {
                let id = format!("m-{file}-{n}");
                body.push_str(&format!(
                    "{{\"type\":\"assistant\",\"pad\":\"{pad}\",\"message\":{{\"id\":\"{id}\",\"usage\":{{\"input_tokens\":3,\"output_tokens\":2}}}}}}\n"
                ));
                expected += 5;
            }
            fs::write(dir.join(format!("s{file}.jsonl")), body).unwrap();
        }
        let total: u64 = (0..2)
            .map(|file| {
                fs::metadata(dir.join(format!("s{file}.jsonl")))
                    .unwrap()
                    .len()
            })
            .sum();
        assert!(total > 64 * 1024 * 1024, "fixture must exceed the old cap");

        let report = collect(home.path());
        let claude = agent(&report, "claude");
        assert_eq!(claude.total_tokens, Some(expected));
        assert_eq!(claude.sessions, Some(2));
        assert_eq!(
            claude.coverage,
            Some(TokenCoverage {
                complete: true,
                files_read: 2,
                files_found: 2
            })
        );
        assert_eq!(claude.provenance.quality, "partial");
    }

    #[test]
    fn a_later_pass_reads_only_the_bytes_appended() {
        let home = tempfile::tempdir().unwrap();
        let dir = claude_dir(home.path());
        let first = msg("a", 10, 1);
        fs::write(dir.join("s.jsonl"), first.as_bytes()).unwrap();
        let mut scanner = TokenScanner::new();
        assert_eq!(
            agent(&scanner.scan(home.path()), "claude").total_tokens,
            Some(11)
        );

        let added = msg("b", 20, 2);
        append(&dir.join("s.jsonl"), &added);
        // A pass that re-read the whole file would not fit in this budget.
        scanner.limits.bytes_per_pass = added.len() as u64 + 8;
        let report = scanner.scan(home.path());
        let claude = agent(&report, "claude");
        assert_eq!(claude.total_tokens, Some(33));
        assert_eq!(claude.coverage.map(|c| c.complete), Some(true));
        assert!(!scanner.catching_up());
    }

    #[test]
    fn a_repeated_message_id_across_passes_keeps_one_snapshot() {
        let home = tempfile::tempdir().unwrap();
        let dir = claude_dir(home.path());
        fs::write(dir.join("s.jsonl"), msg("same", 4, 5).as_bytes()).unwrap();
        let mut scanner = TokenScanner::new();
        scanner.scan(home.path());
        append(&dir.join("s.jsonl"), &msg("same", 4, 9));
        let report = scanner.scan(home.path());
        assert_eq!(agent(&report, "claude").total_tokens, Some(13));
    }

    #[test]
    fn a_resumed_session_copy_is_not_counted_twice_across_files() {
        let home = tempfile::tempdir().unwrap();
        let dir = claude_dir(home.path());
        fs::write(dir.join("parent.jsonl"), msg("shared", 7, 3).as_bytes()).unwrap();
        let mut scanner = TokenScanner::new();
        scanner.scan(home.path());
        let mut copy = msg("shared", 7, 3);
        copy.push_str(&msg("new", 1, 1));
        fs::write(dir.join("resumed.jsonl"), copy.as_bytes()).unwrap();
        let report = scanner.scan(home.path());
        assert_eq!(agent(&report, "claude").total_tokens, Some(12));
        assert_eq!(agent(&report, "claude").sessions, Some(2));
    }

    #[test]
    fn a_record_still_being_written_is_read_once_it_completes() {
        let home = tempfile::tempdir().unwrap();
        let dir = claude_dir(home.path());
        let second = msg("two", 5, 5);
        let (head, tail) = second.split_at(second.len() / 2);
        let mut body = msg("one", 1, 1);
        body.push_str(head);
        fs::write(dir.join("s.jsonl"), body.as_bytes()).unwrap();
        let mut scanner = TokenScanner::new();
        let report = scanner.scan(home.path());
        assert_eq!(agent(&report, "claude").total_tokens, Some(2));
        // A half-written record is not a malformed one.
        assert_eq!(
            report.agents[0].coverage.map(|coverage| coverage.complete),
            Some(true)
        );
        append(&dir.join("s.jsonl"), tail);
        let report = scanner.scan(home.path());
        assert_eq!(agent(&report, "claude").total_tokens, Some(12));
    }

    #[test]
    fn a_file_that_shrank_is_dropped_from_the_totals() {
        let home = tempfile::tempdir().unwrap();
        let dir = claude_dir(home.path());
        let mut body = msg("a", 10, 0);
        body.push_str(&msg("b", 20, 0));
        fs::write(dir.join("s.jsonl"), body.as_bytes()).unwrap();
        let mut scanner = TokenScanner::new();
        assert_eq!(
            agent(&scanner.scan(home.path()), "claude").total_tokens,
            Some(30)
        );
        fs::write(dir.join("s.jsonl"), msg("a", 10, 0).as_bytes()).unwrap();
        assert_eq!(
            agent(&scanner.scan(home.path()), "claude").total_tokens,
            Some(10)
        );
    }

    #[test]
    fn a_file_whose_time_moved_back_is_read_again() {
        let home = tempfile::tempdir().unwrap();
        let dir = claude_dir(home.path());
        let path = dir.join("s.jsonl");
        fs::write(&path, msg("a", 10, 0).as_bytes()).unwrap();
        let mut scanner = TokenScanner::new();
        scanner.scan(home.path());
        // Same length, different content, older time: a restored copy.
        fs::write(&path, msg("b", 50, 0).as_bytes()).unwrap();
        set_mtime(&path, 86_400);
        assert_eq!(
            agent(&scanner.scan(home.path()), "claude").total_tokens,
            Some(50)
        );
    }

    #[test]
    fn bytes_rewritten_in_place_are_detected_even_when_the_file_grew() {
        let home = tempfile::tempdir().unwrap();
        let dir = claude_dir(home.path());
        let path = dir.join("s.jsonl");
        fs::write(&path, msg("old", 10, 0).as_bytes()).unwrap();
        let mut scanner = TokenScanner::new();
        scanner.scan(home.path());
        let mut rewritten = msg("new", 40, 0);
        rewritten.push_str(&msg("more", 1, 0));
        fs::write(&path, rewritten.as_bytes()).unwrap();
        assert_eq!(
            agent(&scanner.scan(home.path()), "claude").total_tokens,
            Some(41)
        );
    }

    #[test]
    fn a_removed_file_leaves_the_totals() {
        let home = tempfile::tempdir().unwrap();
        let dir = claude_dir(home.path());
        fs::write(dir.join("a.jsonl"), msg("a", 10, 0).as_bytes()).unwrap();
        fs::write(dir.join("b.jsonl"), msg("b", 5, 0).as_bytes()).unwrap();
        let mut scanner = TokenScanner::new();
        assert_eq!(
            agent(&scanner.scan(home.path()), "claude").total_tokens,
            Some(15)
        );
        fs::remove_file(dir.join("b.jsonl")).unwrap();
        let report = scanner.scan(home.path());
        assert_eq!(agent(&report, "claude").total_tokens, Some(10));
        assert_eq!(agent(&report, "claude").sessions, Some(1));
    }

    #[test]
    fn a_byte_budget_is_caught_up_over_passes_newest_files_first() {
        let home = tempfile::tempdir().unwrap();
        let dir = claude_dir(home.path());
        for (name, tokens, ago) in [("old", 1, 300), ("mid", 10, 200), ("new", 100, 100)] {
            let path = dir.join(format!("{name}.jsonl"));
            fs::write(&path, msg(name, tokens, 0).as_bytes()).unwrap();
            set_mtime(&path, ago);
        }
        let one_file = msg("new", 100, 0).len() as u64;
        let mut scanner = TokenScanner::with_limits(limits(100, one_file, 1000));

        let first = scanner.scan(home.path());
        let claude = agent(&first, "claude");
        assert_eq!(claude.total_tokens, Some(100), "newest file comes first");
        assert_eq!(claude.provenance.quality, "sample");
        assert_eq!(
            claude.coverage,
            Some(TokenCoverage {
                complete: false,
                files_read: 1,
                files_found: 3
            })
        );
        assert!(scanner.catching_up());

        let mut last = first;
        for _ in 0..5 {
            if !scanner.catching_up() {
                break;
            }
            last = scanner.scan(home.path());
        }
        let claude = agent(&last, "claude");
        assert_eq!(claude.total_tokens, Some(111));
        assert_eq!(claude.provenance.quality, "partial");
        assert_eq!(
            claude.coverage.map(|coverage| coverage.complete),
            Some(true)
        );
        assert!(!scanner.catching_up());
    }

    #[test]
    fn a_file_cap_reports_a_sample_of_the_newest_files() {
        let home = tempfile::tempdir().unwrap();
        let dir = claude_dir(home.path());
        for (name, tokens, ago) in [("a", 1, 300), ("b", 10, 200), ("c", 100, 100)] {
            let path = dir.join(format!("{name}.jsonl"));
            fs::write(&path, msg(name, tokens, 0).as_bytes()).unwrap();
            set_mtime(&path, ago);
        }
        let report = TokenScanner::with_limits(limits(2, u64::MAX, 1000)).scan(home.path());
        let claude = agent(&report, "claude");
        assert_eq!(claude.total_tokens, Some(110));
        assert_eq!(claude.provenance.quality, "sample");
        assert!(claude.provenance.note.contains("sample"));
        assert_eq!(
            claude.coverage,
            Some(TokenCoverage {
                complete: false,
                files_read: 2,
                files_found: 3
            })
        );
    }

    #[test]
    fn a_full_record_store_reports_a_sample() {
        let home = tempfile::tempdir().unwrap();
        let dir = claude_dir(home.path());
        let mut body = String::new();
        for n in 0..3 {
            body.push_str(&msg(&format!("m{n}"), 1, 0));
        }
        fs::write(dir.join("s.jsonl"), body.as_bytes()).unwrap();
        let report = TokenScanner::with_limits(limits(100, u64::MAX, 2)).scan(home.path());
        let claude = agent(&report, "claude");
        assert_eq!(claude.total_tokens, Some(2));
        assert_eq!(
            claude.coverage.map(|coverage| coverage.complete),
            Some(false)
        );
    }

    #[test]
    fn codex_keeps_one_snapshot_per_session_across_passes_and_copies() {
        let home = tempfile::tempdir().unwrap();
        let live = home.path().join(".codex/sessions/2026");
        let archived = home.path().join(".codex/archived_sessions");
        fs::create_dir_all(&live).unwrap();
        fs::create_dir_all(&archived).unwrap();
        let path = live.join("a.jsonl");
        let mut body = codex_meta("s1");
        body.push_str(&codex_count(10, 5));
        fs::write(&path, body.as_bytes()).unwrap();
        let mut scanner = TokenScanner::new();
        assert_eq!(
            agent(&scanner.scan(home.path()), "codex").total_tokens,
            Some(15)
        );
        // The session grows; the id is in the head, which is not read again.
        append(&path, &codex_count(30, 10));
        let mut copy = codex_meta("s1");
        copy.push_str(&codex_count(12, 6));
        fs::write(archived.join("a-copy.jsonl"), copy.as_bytes()).unwrap();
        let report = scanner.scan(home.path());
        let codex = agent(&report, "codex");
        assert_eq!(codex.total_tokens, Some(40));
        assert_eq!(codex.sessions, Some(1));
        assert_eq!(codex.coverage.map(|coverage| coverage.files_found), Some(2));
    }

    #[test]
    fn more_codex_sessions_than_the_old_cap_allowed_are_all_counted() {
        // Reported live: 18 sessions shown for 201 history files.
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join(".codex/sessions");
        fs::create_dir_all(&dir).unwrap();
        for n in 0..201 {
            let mut body = codex_meta(&format!("s{n}"));
            body.push_str(&"x".repeat(0));
            body.push_str(&codex_count(2, 1));
            fs::write(dir.join(format!("{n}.jsonl")), body.as_bytes()).unwrap();
        }
        let report = collect(home.path());
        let codex = agent(&report, "codex");
        assert_eq!(codex.sessions, Some(201));
        assert_eq!(codex.total_tokens, Some(603));
    }

    #[test]
    fn range_reads_start_at_a_record_boundary_and_report_where_they_ended() {
        let first = msg("one", 1, 0);
        let second = msg("two", 2, 0);
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), format!("{first}{second}")).unwrap();
        let mut ids = Vec::new();
        let mut handle = open_source_file(file.path()).unwrap();
        let outcome = for_each_json_line::<ClaudeLine>(
            &mut handle,
            first.len() as u64,
            (first.len() + second.len()) as u64,
            |line| ids.push(line.message.and_then(|message| message.id).unwrap()),
        );
        assert_eq!(ids, vec!["two"]);
        assert_eq!(outcome.end, (first.len() + second.len()) as u64);
        assert!(!outcome.had_error && !outcome.skipped_oversized);
    }

    #[test]
    fn oversized_jsonl_record_is_drained_with_bounded_memory() {
        let mut body = vec![b'x'; MAX_BYTES_PER_LINE + 100];
        body.push(b'\n');
        body.extend_from_slice(b"{}\n");
        let mut reader = BufReader::new(std::io::Cursor::new(body));
        let mut line = Vec::new();
        let read = read_bounded_line(&mut reader, &mut line).unwrap().unwrap();
        assert!(read.oversized && read.terminated);
        assert_eq!(read.bytes, (MAX_BYTES_PER_LINE + 101) as u64);
        assert!(line.len() <= MAX_BYTES_PER_LINE + 1);
        let read = read_bounded_line(&mut reader, &mut line).unwrap().unwrap();
        assert!(!read.oversized && read.terminated);
        assert_eq!(line, b"{}\n");
    }

    #[test]
    fn a_skipped_oversized_record_marks_the_figures_as_a_sample() {
        let home = tempfile::tempdir().unwrap();
        let dir = claude_dir(home.path());
        let mut body = "x".repeat(MAX_BYTES_PER_LINE + 10);
        body.push('\n');
        body.push_str(&msg("a", 4, 0));
        fs::write(dir.join("s.jsonl"), body.as_bytes()).unwrap();
        let report = collect(home.path());
        let claude = agent(&report, "claude");
        assert_eq!(claude.total_tokens, Some(4));
        assert_eq!(
            claude.coverage.map(|coverage| coverage.complete),
            Some(false)
        );
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
