//! One decision at a time, for a reader who asks "what did my agent try, and
//! what should I do about it".
//!
//! [`Graph::cases_page`] answers by SESSION: one accordion per session, its
//! commands inside, capped at 500. On a real machine that was one session
//! holding 15,390 decisions, ten sessions holding none, and a flagged command
//! somewhere on page 31 of an accordion. This module answers by DECISION: a
//! flat, newest-first page of the decisions the guard flagged, with the facts
//! a person needs beside each one (which channel screened it, which agent
//! asked when the caller was told, the folder it ran in, and the rule behind
//! the flag), counts that add up, and a cursor that survives a prune.
//!
//! Pure and I/O free like the rest of this crate: the CLI turns these records
//! into sentences, this module only counts and pages.

use crate::{command_session, Graph, Node};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

/// The channel that screened a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionChannel {
    /// An agent's shell hook (`innerwarden hook`).
    Hook,
    /// An MCP connection through the proxy (`innerwarden proxy`).
    Mcp,
    /// A person running `innerwarden check` by hand.
    Check,
}

impl DecisionChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hook => "hook",
            Self::Mcp => "mcp",
            Self::Check => "check",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "hook" => Some(Self::Hook),
            "mcp" => Some(Self::Mcp),
            "check" => Some(Self::Check),
            _ => None,
        }
    }
}

/// Where a screened command came from, as the recording path knows it.
///
/// Every field is optional. `agent` in particular is written only when the
/// caller was TOLD which agent it serves (a `--agent` flag the connect step
/// wrote); it is never inferred from the shape of a payload, because other
/// agents copy the shapes of the ones this product knows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecisionOrigin {
    pub channel: Option<DecisionChannel>,
    /// A lowercase agent id (`claude-code`, `cursor`).
    pub agent: Option<String>,
    /// The folder the command ran in, as a BASENAME. A path is refused.
    pub project: Option<String>,
    /// The ids of the rules behind the verdict, primary first.
    pub rules: Vec<String>,
}

const MAX_AGENT_CHARS: usize = 64;
const MAX_PROJECT_CHARS: usize = 120;
const MAX_RULES: usize = 16;
const MAX_RULE_CHARS: usize = 64;

fn valid_agent(agent: &str) -> bool {
    !agent.is_empty()
        && agent.len() <= MAX_AGENT_CHARS
        && agent
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

fn valid_project(project: &str) -> bool {
    let count = project.chars().count();
    count > 0
        && count <= MAX_PROJECT_CHARS
        && !project.contains(['/', '\\'])
        && project != "."
        && project != ".."
        && !project.chars().any(char::is_control)
}

fn valid_rule(rule: &str) -> bool {
    !rule.is_empty()
        && rule.len() <= MAX_RULE_CHARS
        && rule
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
}

impl DecisionOrigin {
    /// Write the fields this origin carries onto a command node's attributes.
    /// A field that fails its shape check is dropped, never repaired: a record
    /// with no agent is honest, one with a guessed agent is not.
    pub(crate) fn write_attrs(&self, attrs: &mut BTreeMap<String, String>) {
        if let Some(channel) = self.channel {
            attrs.insert("channel".into(), channel.as_str().into());
        }
        if let Some(agent) = self.agent.as_deref().filter(|agent| valid_agent(agent)) {
            attrs.insert("agent".into(), agent.into());
        }
        if let Some(project) = self
            .project
            .as_deref()
            .map(str::trim)
            .filter(|project| valid_project(project))
        {
            attrs.insert("project".into(), project.into());
        }
        let mut rules: Vec<&str> = Vec::new();
        for rule in &self.rules {
            let rule = rule.trim();
            if valid_rule(rule) && !rules.contains(&rule) {
                rules.push(rule);
            }
            if rules.len() == MAX_RULES {
                break;
            }
        }
        if !rules.is_empty() {
            attrs.insert("rules".into(), rules.join(","));
        }
    }
}

/// What finally happened to a decision, as one key. The same keys the lane
/// cards split a count by, so a row and the bar above it can never disagree.
pub const OUTCOME_KEYS: [&str; 7] = [
    "refused_before_run",
    "unsafe_may_have_run",
    "would_have_refused",
    "flagged_ran",
    "allowed",
    "checked_only",
    "unplaced",
];

fn attr<'a>(node: &'a Node, key: &str) -> Option<&'a str> {
    node.attrs.get(key).map(String::as_str)
}

/// The outcome key of one command node.
///
/// Outcome first, then verdict: a refusal is a refusal whatever the verdict
/// said, and "it ran" is split by what the rules thought of it. A check by
/// hand ran nothing. A node that never recorded an outcome (every record older
/// than the field) is `unplaced`, never `allowed`: absence is not an allow.
pub fn outcome_key(node: &Node) -> &'static str {
    if attr(node, "mode_at_decision") == Some("check") {
        return "checked_only";
    }
    match attr(node, "outcome") {
        Some("blocked") => "refused_before_run",
        Some("would_block") => "would_have_refused",
        Some("screened") => "checked_only",
        Some("allowed") => match attr(node, "recommendation") {
            Some("deny") => "unsafe_may_have_run",
            Some("review") => "flagged_ran",
            Some("allow") => "allowed",
            _ => "unplaced",
        },
        _ => "unplaced",
    }
}

/// A decision the guard flagged: the rules said deny or review, or the guard
/// refused it (or would have).
pub fn is_flagged(node: &Node) -> bool {
    matches!(attr(node, "recommendation"), Some("deny" | "review"))
        || matches!(attr(node, "outcome"), Some("blocked" | "would_block"))
}

/// A flagged decision an AGENT made. A command a person checked by hand with
/// `innerwarden check` is not something the agent did, so it is left out of
/// every "flagged" count and list unless the reader asks for checks.
pub fn is_flagged_agent_action(node: &Node) -> bool {
    is_flagged(node) && outcome_key(node) != "checked_only"
}

/// The prefix this CLI writes before an MCP tool call's summary.
const MCP_LABEL_PREFIX: &str = "MCP · ";

/// The channel of a node: the one it recorded, or, for a node written before
/// the field existed, the one this producer's own formats name. A check by
/// hand records its mode; an MCP call records the proxy's session prefix and
/// label prefix; anything else the guardrail recorded came through a hook.
pub fn channel_of(node: &Node) -> &'static str {
    if let Some(channel) = attr(node, "channel").and_then(DecisionChannel::parse) {
        return channel.as_str();
    }
    if attr(node, "mode_at_decision") == Some("check") {
        return "check";
    }
    let session = command_session(&node.id).unwrap_or_default();
    if node.label.starts_with(MCP_LABEL_PREFIX) || session.starts_with("mcp:") {
        return "mcp";
    }
    match attr(node, "source") {
        None | Some("guardrail") => "hook",
        Some(_) => "unknown",
    }
}

fn rules_of(node: &Node) -> Vec<String> {
    attr(node, "rules")
        .map(|rules| {
            rules
                .split(',')
                .filter(|rule| valid_rule(rule))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// The separator this CLI joins a verdict's reasons with (see the agent
/// guard's `analyze_command`).
const REASON_SEPARATOR: &str = "; ";

fn explanation_of(node: &Node) -> &str {
    attr(node, "explanation").unwrap_or("").trim()
}

/// FNV-1a, 64 bit: a stable, dependency-free digest for grouping equal text.
/// Equality grouping only; nothing here is a security boundary.
fn fnv64(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

/// The key a decision's reason is grouped under: its primary rule id when the
/// node recorded one, and otherwise the whole explanation, compared for
/// equality. Nothing is parsed out of the prose: two records with the same
/// reasons in a different order are two groups, which is the honest cost of a
/// record older than the rule ids.
pub fn reason_key(node: &Node) -> String {
    if let Some(primary) = rules_of(node).into_iter().next() {
        return format!("rule:{primary}");
    }
    let explanation = explanation_of(node);
    if explanation.is_empty() {
        return "none".into();
    }
    format!("text:{:016x}", fnv64(explanation))
}

/// The words of a decision's first reason: the first clause of the
/// explanation, in the join format this CLI writes.
pub fn reason_words(node: &Node) -> String {
    explanation_of(node)
        .split(REASON_SEPARATOR)
        .next()
        .unwrap_or("")
        .trim()
        .to_string()
}

/// How many reasons the decision carried beyond its first.
pub fn reasons_more(node: &Node) -> usize {
    let rules = rules_of(node);
    if !rules.is_empty() {
        return rules.len() - 1;
    }
    let explanation = explanation_of(node);
    if explanation.is_empty() {
        return 0;
    }
    explanation
        .split(REASON_SEPARATOR)
        .count()
        .saturating_sub(1)
}

fn recorded_at_ms(node: &Node) -> Option<u64> {
    attr(node, "recorded_at_ms").and_then(|ms| ms.parse().ok())
}

fn seq_of(node: &Node) -> usize {
    attr(node, "seq")
        .and_then(|seq| seq.parse().ok())
        .or_else(|| {
            node.id
                .rsplit_once(':')
                .and_then(|(_, seq)| seq.parse().ok())
        })
        .unwrap_or(0)
}

/// The order of the list: newest recorded first, then by session and step,
/// newest step first. A node with no recorded time (older than the field)
/// sorts after every timed one. Built only from values a prune cannot change,
/// so a cursor taken before a prune still points at the same place after it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct OrderKey {
    ms: u64,
    session: String,
    seq: usize,
    id: String,
}

fn order_key(node: &Node) -> OrderKey {
    OrderKey {
        ms: recorded_at_ms(node).unwrap_or(0),
        session: command_session(&node.id).unwrap_or_default().to_string(),
        seq: seq_of(node),
        id: node.id.clone(),
    }
}

/// Where the next page starts: the last item of the previous one. Opaque to
/// the reader; it names a place in the order, never a position, so a prune
/// that drops the oldest material between two reads shifts nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionCursor {
    ms: u64,
    id: String,
}

impl DecisionCursor {
    pub fn encode(&self) -> String {
        let hex: String = self.id.bytes().map(|b| format!("{b:02x}")).collect();
        format!("{}-{hex}", self.ms)
    }

    /// `None` for anything this module did not write.
    pub fn parse(value: &str) -> Option<Self> {
        let (ms, hex) = value.split_once('-')?;
        let ms: u64 = ms.parse().ok()?;
        if hex.is_empty() || hex.len() % 2 != 0 || hex.len() > 1_024 {
            return None;
        }
        let bytes: Option<Vec<u8>> = (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(hex.get(at..at + 2)?, 16).ok())
            .collect();
        let id = String::from_utf8(bytes?).ok()?;
        if !id.starts_with("cmd:") {
            return None;
        }
        Some(Self { ms, id })
    }

    fn key(&self) -> OrderKey {
        let session = command_session(&self.id).unwrap_or_default().to_string();
        let seq = self
            .id
            .rsplit_once(':')
            .and_then(|(_, seq)| seq.parse().ok())
            .unwrap_or(0);
        OrderKey {
            ms: self.ms,
            session,
            seq,
            id: self.id.clone(),
        }
    }
}

/// One decision, with everything a case needs and nothing it has to parse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionRecord {
    pub id: String,
    pub session: String,
    pub seq: usize,
    pub command: String,
    /// True when the stored label was cut to fit the record.
    pub command_shortened: bool,
    pub channel: &'static str,
    pub agent: Option<String>,
    pub project: Option<String>,
    pub recommendation: String,
    pub outcome: String,
    pub mode_at_decision: String,
    pub outcome_key: &'static str,
    pub recorded_at_ms: Option<u64>,
    pub decided_by: String,
    pub risk: Option<i64>,
    pub reason_key: String,
    pub reason_words: String,
    pub reasons_more: usize,
    pub rules: Vec<String>,
    pub categories: Vec<String>,
    pub asi: Vec<String>,
    pub explanation: String,
    pub flagged: bool,
}

/// A neighbour of a case in its session, for "Around it".
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionBrief {
    pub id: String,
    pub command: String,
    pub outcome_key: &'static str,
    pub recorded_at_ms: Option<u64>,
    pub flagged: bool,
}

/// What a session holds, counted over the whole record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SessionFacts {
    /// The agent the newest decision in the session named, when any did.
    pub agent: Option<String>,
    /// The channel of the newest decision in the session.
    pub channel: &'static str,
    pub project: Option<String>,
    pub decisions: usize,
    pub flagged: usize,
    pub first_at_ms: Option<u64>,
    pub last_at_ms: Option<u64>,
}

/// How far back the record goes, and how much it holds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RecordSpan {
    pub decisions: usize,
    /// Flagged decisions an agent made: checks by hand are not in here.
    pub flagged: usize,
    /// Decisions that were a check by hand (`innerwarden check`).
    pub checked: usize,
    pub oldest_at_ms: Option<u64>,
    pub newest_at_ms: Option<u64>,
}

/// One reason, counted per DECISION: a decision counts once, under its
/// primary reason, however many categories it also triggered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReasonCount {
    pub key: String,
    pub words: String,
    /// The rule ids of the newest decision under this key.
    pub rules: Vec<String>,
    pub count: usize,
}

/// What a page asks for. Every filter narrows; none widens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionQuery {
    /// Only decisions the guard flagged (the default for a case list).
    pub flagged_only: bool,
    pub outcome: Option<String>,
    pub verdict: Option<String>,
    pub reason: Option<String>,
    /// Leave one reason out: the reader hid it from the list. A view only;
    /// the guard keeps flagging it.
    pub reason_not: Option<String>,
    pub session: Option<String>,
    /// A case-insensitive substring of the command.
    pub text: Option<String>,
    pub cursor: Option<DecisionCursor>,
    pub limit: usize,
}

impl Default for DecisionQuery {
    fn default() -> Self {
        Self {
            flagged_only: true,
            outcome: None,
            verdict: None,
            reason: None,
            reason_not: None,
            session: None,
            text: None,
            cursor: None,
            limit: 25,
        }
    }
}

/// Upper bound on one page, so a request can never ask for the whole record.
pub const MAX_DECISIONS_PAGE: usize = 50;

/// How many reasons a page names; the rest are counted in `reasons_distinct`.
pub const REASONS_SHOWN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionsPage {
    pub items: Vec<DecisionRecord>,
    pub next_cursor: Option<String>,
    /// Decisions matching every filter.
    pub total: usize,
    /// Flagged decisions an agent made in the whole record, whatever the
    /// filters. Checks by hand are not counted.
    pub flagged_total: usize,
    /// The matching decisions by outcome, with the outcome filter set aside, so
    /// the bar beside a filtered list still shows every outcome. Adds up to
    /// `total` when no outcome filter is set.
    pub by_outcome: BTreeMap<&'static str, usize>,
    /// The most frequent reasons among the flagged decisions, with every filter
    /// but the reason applied.
    pub reasons: Vec<ReasonCount>,
    pub reasons_distinct: usize,
    pub record: RecordSpan,
    /// The sessions of the items on this page, counted over the whole record.
    pub sessions: BTreeMap<String, SessionFacts>,
}

/// One flagged decision, reduced to what a count by concern needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FlaggedSummary {
    pub outcome_key: &'static str,
    pub rules: Vec<String>,
    /// The words of its first reason, for a record older than rule ids.
    pub reason_words: String,
}

/// A decision and the commands just before and after it in its session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionDetail {
    pub item: DecisionRecord,
    pub before: Vec<DecisionBrief>,
    pub after: Vec<DecisionBrief>,
    pub session: SessionFacts,
}

/// The agent's commands over a window, split by outcome: the one tally the
/// Overview's agent card counts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Tally {
    pub count: usize,
    pub parts: BTreeMap<&'static str, usize>,
    pub flagged: usize,
    /// The newest flagged decision in the window.
    pub latest_flagged: Option<DecisionRecord>,
    /// Every command counted ran in monitor mode.
    pub all_monitor: bool,
}

/// The keys the agent's tally splits by, in reading order: what InnerWarden
/// refused, what ran while judged unsafe, what it would have refused, what
/// ran while flagged, what was allowed, and what the record cannot place.
pub const TALLY_KEYS: [&str; 6] = [
    "refused_before_run",
    "unsafe_may_have_run",
    "would_have_refused",
    "flagged_ran",
    "allowed",
    "unplaced",
];

struct Row<'a> {
    node: &'a Node,
    key: OrderKey,
    flagged: bool,
    outcome: &'static str,
    reason: String,
    session: &'a str,
}

fn session_matches(filter: &str, session: &str) -> bool {
    let filter = filter.strip_prefix("session:").unwrap_or(filter);
    filter == session
}

impl Graph {
    fn command_rows(&self) -> Vec<Row<'_>> {
        self.nodes
            .iter()
            .filter(|node| node.kind == "command")
            .map(|node| Row {
                node,
                key: order_key(node),
                flagged: is_flagged(node),
                outcome: outcome_key(node),
                reason: reason_key(node),
                session: command_session(&node.id).unwrap_or_default(),
            })
            .collect()
    }

    fn decision_record(&self, node: &Node, out: &HashMap<&str, Vec<&str>>) -> DecisionRecord {
        let linked = |kind: &str| -> Vec<String> {
            let mut labels: Vec<String> = out
                .get(node.id.as_str())
                .into_iter()
                .flatten()
                .filter_map(|to| self.nodes.iter().find(|n| n.id == *to))
                .filter(|n| n.kind == kind)
                .map(|n| n.label.clone())
                .collect();
            labels.dedup();
            labels
        };
        let text = |key: &str| attr(node, key).unwrap_or("unknown").to_string();
        DecisionRecord {
            id: node.id.clone(),
            session: command_session(&node.id).unwrap_or_default().to_string(),
            seq: seq_of(node),
            command: node.label.clone(),
            command_shortened: node.label.ends_with('…') && node.label.chars().count() >= 120,
            channel: channel_of(node),
            agent: attr(node, "agent")
                .filter(|agent| valid_agent(agent))
                .map(str::to_string),
            project: attr(node, "project")
                .filter(|project| valid_project(project))
                .map(str::to_string),
            recommendation: text("recommendation"),
            outcome: text("outcome"),
            mode_at_decision: text("mode_at_decision"),
            outcome_key: outcome_key(node),
            recorded_at_ms: recorded_at_ms(node),
            decided_by: text("decided_by"),
            risk: attr(node, "risk").and_then(|risk| risk.parse().ok()),
            reason_key: reason_key(node),
            reason_words: reason_words(node),
            reasons_more: reasons_more(node),
            rules: rules_of(node),
            categories: linked("category"),
            asi: linked("asi"),
            explanation: explanation_of(node).to_string(),
            flagged: is_flagged(node),
        }
    }

    /// Out-edges to categories and OWASP ids, by command id. Built once per
    /// read, and only over the edges that can carry them.
    fn linked_edges(&self) -> HashMap<&str, Vec<&str>> {
        let mut out: HashMap<&str, Vec<&str>> = HashMap::new();
        for edge in &self.edges {
            if edge.kind == "triggered" || edge.kind == "flags" {
                out.entry(edge.from.as_str())
                    .or_default()
                    .push(edge.to.as_str());
            }
        }
        out
    }

    fn session_facts(&self, rows: &[Row<'_>]) -> HashMap<String, SessionFacts> {
        let mut facts: HashMap<String, (SessionFacts, OrderKey)> = HashMap::new();
        for row in rows {
            let entry = facts
                .entry(row.session.to_string())
                .or_insert_with(|| (SessionFacts::default(), row.key.clone()));
            let (session, newest) = entry;
            session.decisions += 1;
            if row.flagged && row.outcome != "checked_only" {
                session.flagged += 1;
            }
            if let Some(ms) = recorded_at_ms(row.node) {
                session.first_at_ms = Some(session.first_at_ms.map_or(ms, |first| first.min(ms)));
                session.last_at_ms = Some(session.last_at_ms.map_or(ms, |last| last.max(ms)));
            }
            if session.decisions == 1 || row.key >= *newest {
                *newest = row.key.clone();
                session.channel = channel_of(row.node);
                if let Some(agent) = attr(row.node, "agent").filter(|agent| valid_agent(agent)) {
                    session.agent = Some(agent.to_string());
                }
                if let Some(project) =
                    attr(row.node, "project").filter(|project| valid_project(project))
                {
                    session.project = Some(project.to_string());
                }
            }
        }
        facts
            .into_iter()
            .map(|(session, (facts, _))| (session, facts))
            .collect()
    }

    /// The newest decision each agent is NAMED on, by agent id. A decision
    /// that names no agent (every record older than the field, and every hook
    /// line that does not say) counts for none: this is "last screened" for an
    /// agent the record identifies, never a guess.
    pub fn agents_last_seen(&self) -> BTreeMap<String, u64> {
        let mut seen: BTreeMap<String, u64> = BTreeMap::new();
        for node in self.nodes.iter().filter(|node| node.kind == "command") {
            let (Some(agent), Some(ms)) = (
                attr(node, "agent").filter(|agent| valid_agent(agent)),
                recorded_at_ms(node),
            ) else {
                continue;
            };
            let newest = seen.entry(agent.to_string()).or_insert(ms);
            *newest = (*newest).max(ms);
        }
        seen
    }

    /// The newest decision each CHANNEL screened (`hook`, `mcp`), whether or
    /// not it named its agent: proof a screening path is working, for a hook
    /// written before hooks named their agent.
    pub fn channels_last_seen(&self) -> BTreeMap<&'static str, u64> {
        self.channel_times(false)
    }

    /// The newest decision each channel screened that names NO agent. A
    /// channel absent here holds only named decisions, so an agent none of
    /// them names has screened nothing through it.
    pub fn unnamed_channels_last_seen(&self) -> BTreeMap<&'static str, u64> {
        self.channel_times(true)
    }

    fn channel_times(&self, unnamed_only: bool) -> BTreeMap<&'static str, u64> {
        let mut seen: BTreeMap<&'static str, u64> = BTreeMap::new();
        for node in self.nodes.iter().filter(|node| node.kind == "command") {
            if unnamed_only && attr(node, "agent").is_some_and(valid_agent) {
                continue;
            }
            let channel = channel_of(node);
            if channel != "hook" && channel != "mcp" {
                continue;
            }
            let Some(ms) = recorded_at_ms(node) else {
                continue;
            };
            let newest = seen.entry(channel).or_insert(ms);
            *newest = (*newest).max(ms);
        }
        seen
    }

    /// One entry per flagged decision an agent made: what happened to it and
    /// the rules behind it, for the caller to count by what it reached for.
    /// Cheap: no linked labels, no sentence.
    pub fn flagged_summaries(&self) -> Vec<FlaggedSummary> {
        self.nodes
            .iter()
            .filter(|node| node.kind == "command" && is_flagged_agent_action(node))
            .map(|node| FlaggedSummary {
                outcome_key: outcome_key(node),
                rules: rules_of(node),
                reason_words: reason_words(node),
            })
            .collect()
    }

    /// How far back the record goes and how much of it the guard flagged.
    pub fn record_span(&self) -> RecordSpan {
        let mut span = RecordSpan::default();
        for node in self.nodes.iter().filter(|node| node.kind == "command") {
            span.decisions += 1;
            if is_flagged_agent_action(node) {
                span.flagged += 1;
            }
            if outcome_key(node) == "checked_only" {
                span.checked += 1;
            }
            if let Some(ms) = recorded_at_ms(node) {
                span.oldest_at_ms = Some(span.oldest_at_ms.map_or(ms, |oldest| oldest.min(ms)));
                span.newest_at_ms = Some(span.newest_at_ms.map_or(ms, |newest| newest.max(ms)));
            }
        }
        span
    }

    /// The agent's commands recorded at or after `from_ms`, split by outcome.
    ///
    /// A check by hand is not something an agent did, so it is left out. A
    /// node with no recorded time cannot be placed in a window: it is in the
    /// record's count and in no tally. The parts add up to `count` by
    /// construction, one key per node.
    pub fn agent_actions_tally(&self, from_ms: u64) -> Tally {
        let mut tally = Tally {
            all_monitor: true,
            ..Tally::default()
        };
        let mut latest: Option<(&Node, OrderKey)> = None;
        for node in self.nodes.iter().filter(|node| node.kind == "command") {
            if attr(node, "mode_at_decision") == Some("check") {
                continue;
            }
            let Some(ms) = recorded_at_ms(node) else {
                continue;
            };
            if ms < from_ms {
                continue;
            }
            tally.count += 1;
            let key = match outcome_key(node) {
                "checked_only" => "unplaced",
                other => other,
            };
            *tally.parts.entry(key).or_insert(0) += 1;
            if attr(node, "mode_at_decision") != Some("monitor") {
                tally.all_monitor = false;
            }
            if is_flagged(node) {
                tally.flagged += 1;
                let order = order_key(node);
                if latest.as_ref().is_none_or(|(_, newest)| order > *newest) {
                    latest = Some((node, order));
                }
            }
        }
        if tally.count == 0 {
            tally.all_monitor = false;
        }
        let out = self.linked_edges();
        tally.latest_flagged = latest.map(|(node, _)| self.decision_record(node, &out));
        tally
    }

    /// One page of decisions, newest first. See [`DecisionQuery`] and
    /// [`DecisionsPage`] for what each count covers.
    pub fn decisions_page(&self, query: &DecisionQuery) -> DecisionsPage {
        let rows = self.command_rows();
        let text = query
            .text
            .as_deref()
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_lowercase);
        let verdict = query.verdict.as_deref();
        // A check by hand is flagged only when the reader asks for checks: it
        // is not something the agent did, and the counts beside the list (the
        // Overview's agent card among them) are about the agent.
        let wants_checks = query.outcome.as_deref() == Some("checked_only");
        // Every filter except the outcome and the reason, which each have a
        // count that sets its own filter aside.
        let base = |row: &Row<'_>| {
            (!query.flagged_only
                || (row.flagged && (wants_checks || row.outcome != "checked_only")))
                && verdict.is_none_or(|verdict| {
                    attr(row.node, "recommendation").unwrap_or("unknown") == verdict
                })
                && query
                    .session
                    .as_deref()
                    .is_none_or(|session| session_matches(session, row.session))
                && text
                    .as_deref()
                    .is_none_or(|text| row.node.label.to_lowercase().contains(text))
        };
        let outcome_ok = |row: &Row<'_>| query.outcome.as_deref().is_none_or(|o| row.outcome == o);
        let reason_ok = |row: &Row<'_>| {
            query.reason.as_deref().is_none_or(|r| row.reason == r)
                && query.reason_not.as_deref().is_none_or(|r| row.reason != r)
        };

        let mut by_outcome: BTreeMap<&'static str, usize> = BTreeMap::new();
        let mut reasons: HashMap<&str, (usize, &OrderKey, &Node)> = HashMap::new();
        let mut matching: Vec<&Row<'_>> = Vec::new();
        let mut flagged_total = 0usize;
        for row in &rows {
            if row.flagged && row.outcome != "checked_only" {
                flagged_total += 1;
            }
            if !base(row) {
                continue;
            }
            if reason_ok(row) {
                *by_outcome.entry(row.outcome).or_insert(0) += 1;
            }
            if row.flagged && outcome_ok(row) {
                let entry = reasons
                    .entry(row.reason.as_str())
                    .or_insert((0, &row.key, row.node));
                entry.0 += 1;
                if row.key > *entry.1 {
                    entry.1 = &row.key;
                    entry.2 = row.node;
                }
            }
            if outcome_ok(row) && reason_ok(row) {
                matching.push(row);
            }
        }
        let total = matching.len();
        matching.sort_by(|a, b| b.key.cmp(&a.key));
        let after = query.cursor.as_ref().map(DecisionCursor::key);
        let limit = query.limit.clamp(1, MAX_DECISIONS_PAGE);
        let mut page: Vec<&Row<'_>> = matching
            .into_iter()
            .filter(|row| after.as_ref().is_none_or(|cursor| row.key < *cursor))
            .take(limit + 1)
            .collect();
        let more = page.len() > limit;
        page.truncate(limit);
        let next_cursor = if more {
            page.last().map(|row| {
                DecisionCursor {
                    ms: row.key.ms,
                    id: row.node.id.clone(),
                }
                .encode()
            })
        } else {
            None
        };

        let mut reason_list: Vec<ReasonCount> = reasons
            .into_iter()
            .map(|(key, (count, _, node))| ReasonCount {
                key: key.to_string(),
                words: reason_words(node),
                rules: rules_of(node),
                count,
            })
            .collect();
        reason_list.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
        let reasons_distinct = reason_list.len();
        reason_list.truncate(REASONS_SHOWN);

        let out = self.linked_edges();
        let facts = self.session_facts(&rows);
        let items: Vec<DecisionRecord> = page
            .iter()
            .map(|row| self.decision_record(row.node, &out))
            .collect();
        let sessions = items
            .iter()
            .filter_map(|item| {
                facts
                    .get(item.session.as_str())
                    .map(|facts| (item.session.clone(), facts.clone()))
            })
            .collect();

        DecisionsPage {
            items,
            next_cursor,
            total,
            flagged_total,
            by_outcome,
            reasons: reason_list,
            reasons_distinct,
            record: self.record_span(),
            sessions,
        }
    }

    /// One decision by id, with its neighbours in its session, or `None` when
    /// the record no longer holds it (a prune dropped it) or never did.
    pub fn decision(&self, id: &str) -> Option<DecisionDetail> {
        let node = self
            .nodes
            .iter()
            .find(|node| node.kind == "command" && node.id == id)?;
        let rows = self.command_rows();
        let session = command_session(id).unwrap_or_default();
        let mut siblings: Vec<&Row<'_>> =
            rows.iter().filter(|row| row.session == session).collect();
        siblings.sort_by_key(|row| (seq_of(row.node), row.node.id.clone()));
        let at = siblings.iter().position(|row| row.node.id == id)?;
        let brief = |row: &&Row<'_>| DecisionBrief {
            id: row.node.id.clone(),
            command: row.node.label.clone(),
            outcome_key: row.outcome,
            recorded_at_ms: recorded_at_ms(row.node),
            flagged: row.flagged,
        };
        let before = siblings[at.saturating_sub(2)..at]
            .iter()
            .map(brief)
            .collect();
        let after = siblings.iter().skip(at + 1).take(1).map(brief).collect();
        let out = self.linked_edges();
        let facts = self.session_facts(&rows);
        Some(DecisionDetail {
            item: self.decision_record(node, &out),
            before,
            after,
            session: facts.get(session).cloned().unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DecisionContext, DecisionMode, DecisionOutcome};
    use serde_json::{json, Value};

    fn verdict(recommendation: &str, explanation: &str) -> Value {
        json!({"recommendation": recommendation, "explanation": explanation})
    }

    fn context(mode: DecisionMode, outcome: DecisionOutcome, ms: u64) -> DecisionContext {
        DecisionContext {
            mode,
            outcome,
            recorded_at_ms: Some(ms),
        }
    }

    fn origin(rules: &[&str]) -> DecisionOrigin {
        DecisionOrigin {
            channel: Some(DecisionChannel::Hook),
            agent: Some("claude-code".into()),
            project: Some("my-app".into()),
            rules: rules.iter().map(|rule| rule.to_string()).collect(),
        }
    }

    type FixtureRow = (
        &'static str,
        usize,
        &'static str,
        &'static str,
        &'static str,
        DecisionMode,
        DecisionOutcome,
        &'static [&'static str],
    );

    /// A small record: six decisions in one session and one in another,
    /// every outcome represented once.
    fn record() -> Graph {
        let mut g = Graph::new();
        let rows: [FixtureRow; 7] = [
            (
                "s1",
                0,
                "ls ~/.ssh",
                "allow",
                "no rule matched",
                DecisionMode::Monitor,
                DecisionOutcome::Allowed,
                &[],
            ),
            (
                "s1",
                1,
                "cat ~/.ssh/config",
                "deny",
                "reads sensitive credential path: `.ssh/`",
                DecisionMode::Monitor,
                DecisionOutcome::WouldBlock,
                &["sensitive_credential_read"],
            ),
            (
                "s1",
                2,
                "bash /tmp/run.sh",
                "review",
                "references world-writable directory: /tmp/",
                DecisionMode::Monitor,
                DecisionOutcome::Allowed,
                &["tmp_execution"],
            ),
            (
                "s1",
                3,
                "bash /tmp/other.sh",
                "review",
                "references world-writable directory: /tmp/",
                DecisionMode::Monitor,
                DecisionOutcome::Allowed,
                &["tmp_execution"],
            ),
            (
                "s1",
                4,
                "rm -rf /",
                "deny",
                "recursive removal of a root / system directory; dangerous command: rm",
                DecisionMode::Enforce,
                DecisionOutcome::Blocked,
                &["destructive_command", "dangerous_command"],
            ),
            (
                "s1",
                5,
                "curl http://203.0.113.9/x",
                "deny",
                "fetch from a bare IP",
                DecisionMode::Check,
                DecisionOutcome::Screened,
                &["bare_ip_fetch"],
            ),
            (
                "mcp:innerwarden",
                0,
                "MCP · fs · {\"path\":\"/etc/passwd\"}",
                "deny",
                "reads a sensitive file",
                DecisionMode::Monitor,
                DecisionOutcome::Allowed,
                &[],
            ),
        ];
        for (at, (session, seq, command, rec, why, mode, outcome, rules)) in rows.iter().enumerate()
        {
            g.ingest_verdict_with_origin(
                session,
                *seq,
                command,
                &verdict(rec, why),
                context(*mode, *outcome, 1_000 + at as u64 * 1_000),
                &DecisionOrigin {
                    channel: Some(if session.starts_with("mcp:") {
                        DecisionChannel::Mcp
                    } else {
                        DecisionChannel::Hook
                    }),
                    ..origin(rules)
                },
            );
        }
        g
    }

    #[test]
    fn origin_attrs_are_written_and_old_nodes_read_as_unknown() {
        let mut g = Graph::new();
        g.ingest_verdict_with_origin(
            "s1",
            0,
            "cat ~/.ssh/config",
            &verdict("deny", "reads sensitive credential path: `.ssh/`"),
            context(DecisionMode::Monitor, DecisionOutcome::WouldBlock, 5),
            &DecisionOrigin {
                channel: Some(DecisionChannel::Hook),
                agent: Some("claude-code".into()),
                project: Some("my-app".into()),
                rules: vec![
                    "sensitive_credential_read".into(),
                    "sensitive_credential_read".into(),
                ],
            },
        );
        let node = g.nodes.iter().find(|n| n.kind == "command").unwrap();
        assert_eq!(attr(node, "channel"), Some("hook"));
        assert_eq!(attr(node, "agent"), Some("claude-code"));
        assert_eq!(attr(node, "project"), Some("my-app"));
        assert_eq!(attr(node, "rules"), Some("sensitive_credential_read"));

        // A node written by the older ingest path carries none of them, and
        // reads as unknown: no agent, no project, no rules.
        let mut old = Graph::new();
        old.ingest_verdict_with_context(
            "s1",
            0,
            "cat ~/.ssh/config",
            &verdict("deny", "reads sensitive credential path: `.ssh/`"),
            context(DecisionMode::Monitor, DecisionOutcome::WouldBlock, 5),
        );
        let node = old.nodes.iter().find(|n| n.kind == "command").unwrap();
        for key in ["channel", "agent", "project", "rules"] {
            assert!(!node.attrs.contains_key(key), "{key} must be absent");
        }
        let page = old.decisions_page(&DecisionQuery::default());
        assert_eq!(page.items[0].agent, None);
        assert_eq!(page.items[0].project, None);
        assert_eq!(
            page.items[0].channel, "hook",
            "a hook is this producer's default channel"
        );
        assert!(page.items[0].reason_key.starts_with("text:"));
    }

    #[test]
    fn origin_refuses_a_path_for_a_project_and_a_malformed_agent() {
        let mut attrs = BTreeMap::new();
        DecisionOrigin {
            channel: None,
            agent: Some("Claude Code".into()),
            project: Some("/Users/someone/my-app".into()),
            rules: vec!["ok_rule".into(), "not a rule".into()],
        }
        .write_attrs(&mut attrs);
        assert!(!attrs.contains_key("agent"));
        assert!(!attrs.contains_key("project"), "a path is never a project");
        assert_eq!(attrs.get("rules").map(String::as_str), Some("ok_rule"));
    }

    #[test]
    fn flagged_page_lists_only_flagged_decisions_newest_first() {
        let g = record();
        let page = g.decisions_page(&DecisionQuery::default());
        let ids: Vec<&str> = page.items.iter().map(|item| item.id.as_str()).collect();
        // The check by hand (s1:5) is not the agent's: it is not listed.
        assert_eq!(
            ids,
            [
                "cmd:mcp:innerwarden:0",
                "cmd:s1:4",
                "cmd:s1:3",
                "cmd:s1:2",
                "cmd:s1:1"
            ]
        );
        assert!(page.items.iter().all(|item| item.flagged));
        assert_eq!(page.total, 5);
        assert_eq!(page.flagged_total, 5);
        assert_eq!(page.record.decisions, 7);
        assert_eq!(page.record.flagged, 5);
        assert_eq!(page.record.checked, 1);
        assert!(page.next_cursor.is_none());
        assert_eq!(page.items[0].channel, "mcp");
        assert_eq!(page.items[0].outcome_key, "unsafe_may_have_run");
        assert_eq!(page.items[1].outcome_key, "refused_before_run");
        assert_eq!(page.items[2].outcome_key, "flagged_ran");
        assert_eq!(page.items[4].outcome_key, "would_have_refused");
    }

    #[test]
    fn a_check_by_hand_is_listed_only_when_the_reader_asks_for_checks() {
        let g = record();
        let checks = g.decisions_page(&DecisionQuery {
            outcome: Some("checked_only".into()),
            ..DecisionQuery::default()
        });
        let ids: Vec<&str> = checks.items.iter().map(|item| item.id.as_str()).collect();
        assert_eq!(ids, ["cmd:s1:5"]);
        assert_eq!(checks.items[0].channel, "hook", "the origin said hook");
        // The whole-record count stays the agent's.
        assert_eq!(checks.flagged_total, 5);
        // The agent's card and the list count the same flagged decisions.
        assert_eq!(g.agent_actions_tally(0).flagged, checks.flagged_total);
        assert_eq!(g.decision("cmd:s1:5").unwrap().session.flagged, 4);
    }

    #[test]
    fn a_hidden_reason_leaves_the_list_and_the_bar_but_not_the_reasons() {
        let g = record();
        let hidden = g.decisions_page(&DecisionQuery {
            reason_not: Some("rule:tmp_execution".into()),
            ..DecisionQuery::default()
        });
        assert_eq!(hidden.total, 3);
        assert!(hidden
            .items
            .iter()
            .all(|item| item.reason_key != "rule:tmp_execution"));
        assert_eq!(hidden.by_outcome.values().sum::<usize>(), 3);
        assert!(
            hidden
                .reasons
                .iter()
                .any(|reason| reason.key == "rule:tmp_execution"),
            "the reasons list keeps the hidden one, so it can be shown again"
        );
        assert_eq!(hidden.flagged_total, 5);
    }

    #[test]
    fn channels_last_seen_reads_every_decision_named_or_not() {
        let mut g = record();
        g.ingest_verdict_with_context(
            "s9",
            0,
            "ls",
            &verdict("allow", ""),
            context(DecisionMode::Monitor, DecisionOutcome::Allowed, 99_000),
        );
        let seen = g.channels_last_seen();
        assert_eq!(seen.get("hook"), Some(&99_000));
        assert_eq!(seen.get("mcp"), Some(&7_000));
        assert!(Graph::new().channels_last_seen().is_empty());
        // Only the node that names nobody is unnamed: every other one in the
        // record names claude-code.
        let unnamed = g.unnamed_channels_last_seen();
        assert_eq!(unnamed.get("hook"), Some(&99_000));
        assert_eq!(unnamed.get("mcp"), None);
    }

    #[test]
    fn flagged_summaries_are_the_agents_flagged_decisions() {
        let g = record();
        let summaries = g.flagged_summaries();
        assert_eq!(summaries.len(), g.record_span().flagged);
        assert!(summaries.iter().all(|s| s.outcome_key != "checked_only"));
        assert!(summaries
            .iter()
            .any(|s| s.rules == ["sensitive_credential_read".to_string()]));
    }

    #[test]
    fn by_outcome_adds_up_to_total() {
        let g = record();
        let page = g.decisions_page(&DecisionQuery::default());
        assert_eq!(page.by_outcome.values().sum::<usize>(), page.total);
        // With an outcome filter the bar keeps every outcome, and the list
        // holds only the one asked for.
        let filtered = g.decisions_page(&DecisionQuery {
            outcome: Some("flagged_ran".into()),
            ..DecisionQuery::default()
        });
        assert_eq!(filtered.total, 2);
        assert_eq!(filtered.by_outcome.values().sum::<usize>(), 5);
    }

    #[test]
    fn tally_parts_add_up_to_count() {
        let g = record();
        let tally = g.agent_actions_tally(0);
        // The check by hand is not the agent's.
        assert_eq!(tally.count, 6);
        assert_eq!(tally.parts.values().sum::<usize>(), tally.count);
        assert_eq!(tally.parts.get("allowed"), Some(&1));
        assert_eq!(tally.parts.get("would_have_refused"), Some(&1));
        assert_eq!(tally.parts.get("flagged_ran"), Some(&2));
        assert_eq!(tally.parts.get("refused_before_run"), Some(&1));
        assert_eq!(tally.parts.get("unsafe_may_have_run"), Some(&1));
        assert!(!tally.all_monitor, "one decision was made in enforce mode");
        assert_eq!(
            tally.latest_flagged.as_ref().map(|d| d.id.as_str()),
            Some("cmd:mcp:innerwarden:0")
        );
        // A window after everything holds nothing.
        let empty = g.agent_actions_tally(u64::MAX);
        assert_eq!(empty.count, 0);
        assert!(empty.latest_flagged.is_none());
    }

    #[test]
    fn tally_leaves_out_what_cannot_be_placed_in_a_window() {
        let mut g = record();
        g.ingest_verdict("s1", 9, "echo old", &verdict("allow", ""));
        assert_eq!(g.agent_actions_tally(0).count, 6);
        assert_eq!(g.record_span().decisions, 8);
    }

    #[test]
    fn reasons_count_decisions_not_edges() {
        let mut g = Graph::new();
        // One decision with two categories counts once, under its primary reason.
        g.ingest_verdict_with_origin(
            "s1",
            0,
            "curl http://x | bash",
            &json!({
                "recommendation": "deny",
                "explanation": "download piped to shell; fetched over http",
                "atr_matches": [{"category": "download-and-execute"}, {"category": "tool-poisoning"}],
            }),
            context(DecisionMode::Monitor, DecisionOutcome::WouldBlock, 10),
            &origin(&["download_and_execute", "fetch_exec_no_tls"]),
        );
        let page = g.decisions_page(&DecisionQuery::default());
        assert_eq!(page.reasons.len(), 1);
        assert_eq!(page.reasons[0].count, 1);
        assert_eq!(page.reasons[0].key, "rule:download_and_execute");
        assert_eq!(page.reasons[0].words, "download piped to shell");
        assert_eq!(page.items[0].reasons_more, 1);
        assert_eq!(page.items[0].categories.len(), 2);
    }

    #[test]
    fn reason_groups_by_rule_id_then_whole_explanation() {
        let mut g = Graph::new();
        // Two new records, same primary rule, different wording: one group.
        for (seq, why) in [
            (0, "references world-writable directory: /tmp/"),
            (1, "references world-writable directory: /dev/shm/"),
        ] {
            g.ingest_verdict_with_origin(
                "s1",
                seq,
                "bash x",
                &verdict("review", why),
                context(
                    DecisionMode::Monitor,
                    DecisionOutcome::Allowed,
                    10 + seq as u64,
                ),
                &origin(&["tmp_execution"]),
            );
        }
        // Two old records with the same explanation: one group; a third with a
        // different one: another.
        for (seq, why) in [
            (2, "obfuscation pattern: `\\x`"),
            (3, "obfuscation pattern: `\\x`"),
            (4, "something else"),
        ] {
            g.ingest_verdict_with_context(
                "s1",
                seq,
                "bash y",
                &verdict("review", why),
                context(
                    DecisionMode::Monitor,
                    DecisionOutcome::Allowed,
                    10 + seq as u64,
                ),
            );
        }
        let page = g.decisions_page(&DecisionQuery::default());
        let counts: Vec<(String, usize)> = page
            .reasons
            .iter()
            .map(|r| (r.key.clone(), r.count))
            .collect();
        assert_eq!(page.reasons_distinct, 3);
        assert_eq!(counts[0], ("rule:tmp_execution".to_string(), 2));
        assert_eq!(counts[1].1, 2);
        assert!(counts[1].0.starts_with("text:"));
        // The reason filter lists exactly that group.
        let only = g.decisions_page(&DecisionQuery {
            reason: Some(counts[1].0.clone()),
            ..DecisionQuery::default()
        });
        assert_eq!(only.total, 2);
        assert_eq!(
            only.reasons_distinct, 3,
            "the reasons card sets its own filter aside"
        );
    }

    #[test]
    fn cursor_pages_without_repeats_and_survives_a_prune_between_pages() {
        let mut g = Graph::new();
        for seq in 0..30usize {
            g.ingest_verdict_with_origin(
                "s1",
                seq,
                &format!("bash /tmp/{seq}.sh"),
                &verdict("review", "references world-writable directory: /tmp/"),
                context(
                    DecisionMode::Monitor,
                    DecisionOutcome::Allowed,
                    1_000 + seq as u64,
                ),
                &origin(&["tmp_execution"]),
            );
        }
        let first = g.decisions_page(&DecisionQuery {
            limit: 10,
            ..DecisionQuery::default()
        });
        assert_eq!(first.items.len(), 10);
        let cursor = DecisionCursor::parse(first.next_cursor.as_deref().unwrap()).unwrap();

        // Drop the five OLDEST command nodes between the two reads, the way
        // `prune` drops from the front.
        let oldest: Vec<String> = g
            .nodes
            .iter()
            .filter(|n| n.kind == "command")
            .take(5)
            .map(|n| n.id.clone())
            .collect();
        g.nodes.retain(|n| !oldest.contains(&n.id));
        g.edges.retain(|e| !oldest.contains(&e.to));

        let second = g.decisions_page(&DecisionQuery {
            limit: 10,
            cursor: Some(cursor),
            ..DecisionQuery::default()
        });
        let first_ids: Vec<&str> = first.items.iter().map(|i| i.id.as_str()).collect();
        let second_ids: Vec<&str> = second.items.iter().map(|i| i.id.as_str()).collect();
        assert!(
            second_ids.iter().all(|id| !first_ids.contains(id)),
            "no item repeats"
        );
        // The next ten survivors, in order, nothing skipped.
        let expected: Vec<String> = (10..20).rev().map(|seq| format!("cmd:s1:{seq}")).collect();
        assert_eq!(
            second_ids,
            expected.iter().map(String::as_str).collect::<Vec<_>>()
        );
        let third = g.decisions_page(&DecisionQuery {
            limit: 10,
            cursor: DecisionCursor::parse(second.next_cursor.as_deref().unwrap()),
            ..DecisionQuery::default()
        });
        assert_eq!(third.items.len(), 5, "only the survivors are left");
        assert!(third.next_cursor.is_none());
    }

    #[test]
    fn a_cursor_this_module_did_not_write_is_refused() {
        assert!(DecisionCursor::parse("").is_none());
        assert!(DecisionCursor::parse("12-zz").is_none());
        assert!(DecisionCursor::parse("x-00").is_none());
        let other = DecisionCursor {
            ms: 1,
            id: "session:s1".into(),
        }
        .encode();
        assert!(
            DecisionCursor::parse(&other).is_none(),
            "only a command id is a place in the list"
        );
        let good = DecisionCursor {
            ms: 7,
            id: "cmd:mcp:a:3".into(),
        };
        assert_eq!(DecisionCursor::parse(&good.encode()), Some(good));
    }

    #[test]
    fn a_session_with_no_commands_is_never_listed() {
        let mut g = record();
        g.upsert_node(Node {
            id: "session:host".into(),
            kind: "session".into(),
            label: "host".into(),
            attrs: BTreeMap::new(),
        });
        let page = g.decisions_page(&DecisionQuery {
            flagged_only: false,
            ..DecisionQuery::default()
        });
        assert!(page.items.iter().all(|item| item.session != "host"));
        assert!(!page.sessions.contains_key("host"));
        assert_eq!(page.total, 7);
    }

    #[test]
    fn agents_last_seen_counts_only_records_that_name_the_agent() {
        let mut g = record();
        // An older node that names nobody changes nothing.
        g.ingest_verdict_with_context(
            "s9",
            0,
            "ls",
            &verdict("allow", ""),
            context(DecisionMode::Monitor, DecisionOutcome::Allowed, 99_000),
        );
        let seen = g.agents_last_seen();
        assert_eq!(seen.get("claude-code"), Some(&7_000));
        assert_eq!(seen.len(), 1);
        assert!(Graph::new().agents_last_seen().is_empty());
    }

    #[test]
    fn record_span_reads_oldest_and_newest() {
        let g = record();
        let span = g.record_span();
        assert_eq!(span.oldest_at_ms, Some(1_000));
        assert_eq!(span.newest_at_ms, Some(7_000));
        assert_eq!(Graph::new().record_span(), RecordSpan::default());
    }

    #[test]
    fn filters_narrow_by_verdict_session_and_text() {
        let g = record();
        let deny = g.decisions_page(&DecisionQuery {
            verdict: Some("deny".into()),
            ..DecisionQuery::default()
        });
        assert_eq!(deny.total, 3, "the deny checked by hand is not listed");
        let session = g.decisions_page(&DecisionQuery {
            session: Some("mcp:innerwarden".into()),
            ..DecisionQuery::default()
        });
        assert_eq!(session.total, 1);
        assert_eq!(session.sessions.len(), 1);
        let text = g.decisions_page(&DecisionQuery {
            text: Some("TMP".into()),
            ..DecisionQuery::default()
        });
        assert_eq!(text.total, 2);
        let all = g.decisions_page(&DecisionQuery {
            flagged_only: false,
            ..DecisionQuery::default()
        });
        assert_eq!(all.total, 7);
    }

    #[test]
    fn decision_answers_with_its_neighbours_or_none_when_pruned() {
        let g = record();
        let detail = g.decision("cmd:s1:2").unwrap();
        assert_eq!(detail.item.command, "bash /tmp/run.sh");
        let before: Vec<&str> = detail.before.iter().map(|b| b.id.as_str()).collect();
        assert_eq!(before, ["cmd:s1:0", "cmd:s1:1"]);
        assert_eq!(detail.after[0].id, "cmd:s1:3");
        assert_eq!(detail.session.decisions, 6);
        assert_eq!(detail.session.flagged, 4);
        assert_eq!(detail.session.agent.as_deref(), Some("claude-code"));
        assert!(g.decision("cmd:s1:99").is_none());
        assert!(g.decision("session:s1").is_none());
        let first = g.decision("cmd:s1:0").unwrap();
        assert!(first.before.is_empty());
    }

    /// The paid agent serves `Graph::overview` as its own `guard/overview` and
    /// adds its own fields beside it. A field added here would collide with
    /// one of those, so the key set is pinned: a change must be deliberate.
    #[test]
    fn overview_json_field_names_are_unchanged() {
        let json = serde_json::to_value(record().overview(5)).unwrap();
        let keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "actual_blocks",
                "allow_verdicts",
                "allowed",
                "blocked",
                "commands",
                "denies_without_block",
                "deny_verdicts",
                "outcomes_unknown",
                "recent_blocks",
                "recent_decisions",
                "review",
                "review_verdicts",
                "screened",
                "sessions",
                "top_categories",
                "unknown_verdicts",
                "would_block",
            ]
        );
        let recent = json["recent_decisions"][0].as_object().unwrap();
        let recent_keys: Vec<&str> = recent.keys().map(String::as_str).collect();
        assert_eq!(
            recent_keys,
            [
                "categories",
                "command",
                "decided_by",
                "id",
                "mode_at_decision",
                "outcome",
                "recommendation",
                "recorded_at_ms",
                "session",
            ]
        );
    }

    #[test]
    fn a_legacy_decision_is_unplaced_never_allowed() {
        let mut g = Graph::new();
        g.ingest_verdict("s1", 0, "rm -rf /tmp/x", &verdict("deny", "x"));
        let page = g.decisions_page(&DecisionQuery::default());
        assert_eq!(page.items[0].outcome_key, "unplaced");
        assert_eq!(page.items[0].recorded_at_ms, None);
    }

    #[test]
    fn channel_is_read_from_this_producers_own_formats_on_old_nodes() {
        let mut g = Graph::new();
        g.ingest_verdict_with_context(
            "mcp:innerwarden",
            0,
            "MCP · fs · {}",
            &verdict("deny", "x"),
            context(DecisionMode::Monitor, DecisionOutcome::WouldBlock, 1),
        );
        g.ingest_verdict_with_context(
            "local",
            0,
            "rm -rf /",
            &verdict("deny", "x"),
            context(DecisionMode::Check, DecisionOutcome::Screened, 2),
        );
        let page = g.decisions_page(&DecisionQuery {
            flagged_only: false,
            ..DecisionQuery::default()
        });
        let channels: Vec<&str> = page.items.iter().map(|item| item.channel).collect();
        assert_eq!(channels, ["check", "mcp"]);
    }
}
