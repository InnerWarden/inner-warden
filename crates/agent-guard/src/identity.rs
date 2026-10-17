//! Which agent is this, how do we know, and which rules apply to it.
//!
//! Pure contract types and decisions. Nothing here reads a file, a process or
//! the environment: every fact is handed in by a caller that read it, so a
//! decision is a function of its inputs and a test can enumerate them. The
//! launcher that writes the record, the hook that reads it and the screens that
//! show it are separate pieces that build on this one.
//!
//! # Two axes, never one list
//!
//! * [`Trust`] is HOW WE KNOW: `declared` (the agent or its settings say so),
//!   `observed` (something outside the agent's control saw it), `confined` (it
//!   runs inside a boundary it cannot leave and whoever built the boundary is
//!   trusted). Each level is claimed only from its own source.
//! * [`Lifecycle`] is WHAT THE OPERATOR DECIDED: `discovered`, `approved`,
//!   `revoked`. A revoked instance keeps the trust it had when it acted.
//!
//! A word for a higher level than `confined` is reserved and deliberately has
//! no variant: it cannot be read from a file or a wire by accident.
//!
//! # A file never raises trust by itself
//!
//! A [`LaunchRecord`] carries LABELS (agent type, project) and the facts the
//! launcher saw. What level those facts earn is decided elsewhere, from facts
//! the reader takes from the kernel ([`judge_trust_in_jail`]). A record that
//! says "confined" has no such field to say it in.
//!
//! # A relaxation is only for a confined instance
//!
//! A per-agent rule that LOOSENS the general policy is honoured only when the
//! instance is `confined` ([`decide`]). The name an agent declares, the flag on
//! its hook line, its environment and its session id are all its own to choose;
//! if any of them could unlock a looser profile, a compromised agent would
//! declare itself the most permissive one. A rule that TIGHTENS is honoured at
//! any trust level, since an agent gains nothing by being held to more.
//!
//! `innerwarden contain --identity` (off by default) writes the record; the
//! hook reads it for its labels; the per-agent profiles ([`crate::profiles`],
//! read only where a profiles file exists) decide with [`decide`].
//!
//! # Who decides that a relaxation applies
//!
//! No reading from inside the jail reaches `confined`, so the hook alone never
//! applies a relaxation. Where InnerWarden Active Defence runs on the same
//! host, the hook ASKS it ([`INSTANCE_DECIDE_ROUTE`]) when its general rules
//! sent a shell command of an instance to review, and the host decides. The
//! hook takes `confined` as the input of [`decide`] only from an answer that
//! says so ([`InstanceDecideAnswer::relaxes`]), keeps the stricter of its own
//! decision and the host's verdict, and never records the answer's word as
//! the instance's trust: the answer is something the agent's process could
//! also have been shown, and the label it leaves says only that the host was
//! asked ([`HOST_TRUST_SOURCE`]).

use std::fmt;
use std::path::{Component, Path};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::mcp::{CommandAnalysis, AGENT_REVIEW_FLOOR};

// ---------------------------------------------------------------------------
// Names and places
// ---------------------------------------------------------------------------

/// The launcher flag that asks for an identified instance.
pub const IDENTITY_FLAG: &str = "--identity";

/// Where the launcher's record appears INSIDE the jail: mounted read-only by
/// the launcher, so the agent inside cannot rewrite it.
pub const JAIL_RECORD_PATH: &str = "/run/innerwarden/instance.json";

/// The variable the launcher sets inside an identified jail to the agent it
/// started the jail for. The hook holds the record's type to it, as it holds
/// it to its own line's `--agent`: a label that can only lower a level.
pub const HOOK_AGENT_ENV: &str = "IW_HOOK_AGENT";

/// The directory, under the user's state home, where the launcher keeps one
/// record per instance OUTSIDE the jail (`<state home>/innerwarden/instances`).
pub const LAUNCHER_RECORD_DIR: &str = "innerwarden/instances";

/// The file name of an instance's record in a records directory, or `None` if
/// `instance_id` is not a well-formed id. An id is the only part of the name the
/// caller does not control, and it is checked before it can become a path.
pub fn instance_record_file(instance_id: &str) -> Option<String> {
    is_instance_id(instance_id).then(|| format!("{instance_id}.json"))
}

/// Every scope the launcher puts an instance in is named
/// `innerwarden-contain-<instance_id>.scope`, user scope and system scope alike.
pub const SCOPE_UNIT_PREFIX: &str = "innerwarden-contain-";

/// The unit name of an instance's scope, or `None` if `instance_id` is not a
/// well-formed id.
pub fn scope_unit_name(instance_id: &str) -> Option<String> {
    is_instance_id(instance_id).then(|| format!("{SCOPE_UNIT_PREFIX}{instance_id}.scope"))
}

/// The cgroup a system scope of `unit` has: directly under the system slice,
/// where only root can create it or move a process into it.
pub fn system_scope_cgroup(unit: &str) -> String {
    format!("/system.slice/{unit}")
}

/// Whether `cgroup_path` is the cgroup of the user scope `unit` of `uid`: a
/// leaf named `unit` somewhere under that user's own manager,
/// `/user.slice/user-<uid>.slice/user@<uid>.service/`.
pub fn is_user_scope_cgroup(cgroup_path: &str, unit: &str, uid: u32) -> bool {
    let manager = format!("/user.slice/user-{uid}.slice/user@{uid}.service/");
    is_absolute_path(cgroup_path)
        && cgroup_path.starts_with(&manager)
        && cgroup_path.ends_with(&format!("/{unit}"))
}

/// The local route a launcher calls, best effort, to ask the Active Defence
/// agent on the same host for a system scope around a new instance.
///
/// The request names the instance and nothing else (no pid, no path, no
/// cgroup): [`system_scope_request`]. Whatever the answer, the launcher
/// records a system scope only when the kernel shows the jail in
/// [`system_scope_cgroup`]; the reply is never taken as that fact.
pub const SYSTEM_SCOPE_ROUTE: &str = "/api/agent/contain-scope";

/// The body of a request to [`SYSTEM_SCOPE_ROUTE`]: `{"instance": "<id>"}`, or
/// `None` if `instance_id` is not a well-formed id.
pub fn system_scope_request(instance_id: &str) -> Option<serde_json::Value> {
    is_instance_id(instance_id).then(|| serde_json::json!({ "instance": instance_id }))
}

/// The local route a launcher calls, best effort, once an identified jail has
/// ended, to tell the Active Defence agent on the same host what the jail's
/// hook screened.
///
/// The hook inside the jail keeps its record in the project, a folder the
/// agent can write, so what the launcher reads there is the jail's own word.
/// The report therefore says `declared` and nothing else can make it say more:
/// [`contained_run_report`] has no trust to pass in. It carries counts and
/// times only, never a command, so a forged project graph can change two
/// numbers in it and nothing else. The launcher never writes the host's
/// shared graph for the jail.
pub const CONTAINED_RUN_ROUTE: &str = "/api/agent/contain-run";

/// Where a [`contained_run_report`]'s counts come from.
pub const CONTAINED_RUN_SOURCE: &str = "project_graph";

/// What the launcher found where the jail's hook keeps its graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JailGraphState {
    /// Read and parsed: the counts are what it holds.
    Read,
    /// Nothing there: the hook recorded nothing.
    Absent,
    /// There and refused (a link, not a regular file, not the user's, too
    /// large, not a graph): no count can be given, which is not zero.
    Unreadable,
}

impl JailGraphState {
    pub fn as_str(self) -> &'static str {
        match self {
            JailGraphState::Read => "read",
            JailGraphState::Absent => "absent",
            JailGraphState::Unreadable => "unreadable",
        }
    }
}

/// One ended run of an identified jail, as the launcher counted it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainedRun<'a> {
    pub instance_id: &'a str,
    /// The launcher's clock just before the jail was started, in ms.
    pub started_ms: u64,
    /// The launcher's clock once the jail had ended, in ms.
    pub ended_ms: u64,
    pub graph: JailGraphState,
    /// Commands the hook recorded for this instance, inside the window.
    pub commands: u32,
    /// The newest of them, in ms.
    pub last_ms: Option<u64>,
    /// Of those commands, the ones the hook recorded as allowed by a
    /// per-agent rule the host decided: an `allow` from the type or the
    /// instance layer, labelled with [`HOST_TRUST_SOURCE`] and a host
    /// decision. The jail's own word, like the other counts.
    pub host_allowances: u32,
    /// The host decisions those commands name, each pair once, at most
    /// [`MAX_HOST_DECISIONS`].
    pub host_decisions: &'a [HostDecisionClaim],
}

/// The most host decisions one [`contained_run_report`] names.
pub const MAX_HOST_DECISIONS: usize = 256;

/// One command a jail's hook recorded as allowed by the host: the host
/// decision it names and the SHA-256, in lowercase hex, of the command text
/// the record holds for it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostDecisionClaim {
    pub decision_id: String,
    pub command_sha256: String,
}

impl HostDecisionClaim {
    /// Both values have their shape: a [`is_decision_id`] and 64 lowercase
    /// hex characters.
    pub fn is_valid(&self) -> bool {
        is_decision_id(&self.decision_id) && is_lower_hex(&self.command_sha256, 64)
    }
}

/// The body of a report to [`CONTAINED_RUN_ROUTE`], or `None` when the run
/// does not describe itself consistently: an id that is not an id, a window
/// that ends before it starts, a newest command outside the window, a count
/// for a graph that was not read, or host allowances that are not a part of
/// the commands counted or do not name their decisions.
///
/// ```json
/// {"instance": "<id>", "source": "project_graph", "trust": "declared",
///  "graph": "read", "commands": 3, "last_ms": 1760000000000,
///  "started_ms": 1759999990000, "ended_ms": 1760000005000}
/// ```
///
/// `host_allowances` and `host_decisions` are added only when the run has
/// any, so the report of a run without them is the body it always was.
pub fn contained_run_report(run: &ContainedRun<'_>) -> Option<serde_json::Value> {
    let window = run.started_ms..=run.ended_ms;
    let mut pairs: Vec<&HostDecisionClaim> = run.host_decisions.iter().collect();
    pairs.sort_unstable();
    pairs.dedup();
    let consistent = is_instance_id(run.instance_id)
        && run.started_ms <= run.ended_ms
        && run.last_ms.is_none_or(|ms| window.contains(&ms))
        && (run.commands == 0) == run.last_ms.is_none()
        && (run.graph == JailGraphState::Read || run.commands == 0)
        && run.host_allowances <= run.commands
        && (run.host_allowances == 0) == run.host_decisions.is_empty()
        && run.host_decisions.len() <= MAX_HOST_DECISIONS
        && run.host_decisions.len() <= run.host_allowances as usize
        && pairs.len() == run.host_decisions.len()
        && run.host_decisions.iter().all(HostDecisionClaim::is_valid);
    consistent.then(|| {
        let mut body = serde_json::json!({
            "instance": run.instance_id,
            "source": CONTAINED_RUN_SOURCE,
            "trust": Trust::Declared.as_str(),
            "graph": run.graph.as_str(),
            "commands": run.commands,
            "last_ms": run.last_ms,
            "started_ms": run.started_ms,
            "ended_ms": run.ended_ms,
        });
        if run.host_allowances > 0 {
            body["host_allowances"] = serde_json::json!(run.host_allowances);
            body["host_decisions"] = serde_json::json!(run.host_decisions);
        }
        body
    })
}

// ---------------------------------------------------------------------------
// Asking the host
// ---------------------------------------------------------------------------

/// The local route a hook in an identified jail calls, at most once per
/// screened shell command and within a short bound, to ask the Active
/// Defence agent on the same host whether a per-agent relaxation applies to
/// a command its general rules sent to review.
///
/// The request is an [`InstanceDecideRequest`] and it carries the command's
/// RAW text: the host judges the command again with its own copy of the
/// engine, and a redacted text would be another command. It goes only to
/// this host's loopback and is never written anywhere by the hook. The answer
/// is an [`InstanceDecideAnswer`]; [`read_host_answer`] says what the hook may
/// take from it. Without an answer that is exactly the contract's, the hook
/// decides as it did before it asked.
pub const INSTANCE_DECIDE_ROUTE: &str = "/api/agent/instance-decide";

/// The only version of the request and of the answer.
pub const INSTANCE_DECIDE_VERSION: u32 = 1;

/// The most signal names one request carries.
pub const MAX_HOOK_SIGNALS: usize = 64;

/// The most bytes of an answer the hook reads.
pub const MAX_INSTANCE_ANSWER_BYTES: usize = 4096;

/// The `trust_source` of every answer, and the label a decision the host
/// answered for carries.
pub const HOST_TRUST_SOURCE: &str = "host";

/// The word the hook records when the host answered 200 with a body that is
/// not the contract's. The hook's own word: it never comes from the wire.
pub const HOST_ANSWER_INVALID: &str = "host_answer_invalid";

/// Where the Active Defence agent publishes the key its local dashboard
/// answers with (see [`parse_spki_pin`]), for the hook to hold the answer's
/// connection to.
pub const AGENT_TLS_SPKI_PATH: &str = "/etc/innerwarden/agent-tls.spki";

/// Where the key appears INSIDE an identified jail. Inside the jail's user
/// namespace the host's owners cannot be told apart (every account but the
/// user's shows as one uid), so the launcher reads [`AGENT_TLS_SPKI_PATH`]
/// outside, with the real owners, and mounts what it read here read-only,
/// beside [`JAIL_RECORD_PATH`]. No key there, no request.
pub const JAIL_SPKI_PIN_PATH: &str = "/run/innerwarden/agent-tls.spki";

/// The most bytes the key file holds: 64 hex characters and a newline.
pub const MAX_SPKI_PIN_BYTES: usize = 65;

/// The key in [`AGENT_TLS_SPKI_PATH`]: the SHA-256 of the DER
/// `SubjectPublicKeyInfo` (outer `SEQUENCE` included) of the certificate the
/// agent's local dashboard presents, as 64 lowercase hex characters,
/// optionally followed by one newline. Anything else is no key.
pub fn parse_spki_pin(bytes: &[u8]) -> Option<[u8; 32]> {
    let text = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let text = std::str::from_utf8(text).ok()?;
    if !is_lower_hex(text, 64) {
        return None;
    }
    let mut pin = [0u8; 32];
    for (index, byte) in pin.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(pin)
}

/// The line [`parse_spki_pin`] reads for `digest`.
pub fn spki_pin_line(digest: &[u8; 32]) -> String {
    let mut line: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    line.push('\n');
    line
}

/// Exactly `len` lowercase hex characters.
fn is_lower_hex(text: &str, len: usize) -> bool {
    text.len() == len
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A host decision id: 32 lowercase hex characters (128 random bits).
pub fn is_decision_id(id: &str) -> bool {
    is_lower_hex(id, 32)
}

/// A session id a request may carry: 1 to 128 of `[A-Za-z0-9_-]`. Any other
/// session the hook has is sent as `null`.
pub fn is_session_label(session: &str) -> bool {
    !session.is_empty()
        && session.len() <= 128
        && session
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A word an answer may hold in `withheld`: 1 to 48 of `[a-z_]`. The hook
/// keeps it as it came, without knowing what it means.
pub fn is_withheld_word(word: &str) -> bool {
    !word.is_empty()
        && word.len() <= 48
        && word.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
}

/// A signal name a request may carry: a name the engine raises
/// ([`crate::mcp::SIGNAL_NAMES`]), an aggravating factor
/// ([`crate::mcp::AGGRAVATING_SIGNAL_NAMES`]), or `atr:<category>` with a
/// category of 1 to 64 of `[a-z0-9_-]`.
pub fn is_hook_signal(name: &str) -> bool {
    if crate::mcp::SIGNAL_NAMES.contains(&name)
        || crate::mcp::AGGRAVATING_SIGNAL_NAMES.contains(&name)
    {
        return true;
    }
    name.strip_prefix("atr:").is_some_and(|category| {
        !category.is_empty()
            && category.len() <= 64
            && category
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    })
}

/// A field that must be present and may be `null`. Without this, serde reads
/// a missing `Option` as `None`, and an answer that left out `withheld` would
/// read as one that withheld nothing.
fn nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// The body of a request to [`INSTANCE_DECIDE_ROUTE`]. Every field is
/// required and none other is read (`deny_unknown_fields`).
///
/// ```json
/// {"v":1,"instance_id":"<id>","claimed_agent_type":"claude-code",
///  "session_id":"<id>","command":"curl http://203.0.113.9/x",
///  "hook_signals":["bare_ip_fetch"],"tainted":false,
///  "hook_verdict":"review","hook_layer":"general"}
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceDecideRequest {
    /// [`INSTANCE_DECIDE_VERSION`].
    pub v: u32,
    /// The instance the hook's own record names.
    pub instance_id: String,
    /// The agent type the hook would apply a profile for. A claim the host
    /// compares, never one it uses.
    #[serde(deserialize_with = "nullable")]
    pub claimed_agent_type: Option<String>,
    /// The session id the agent sent, when it has the shape of
    /// [`is_session_label`]. Only recorded.
    #[serde(deserialize_with = "nullable")]
    pub session_id: Option<String>,
    /// The command as the agent asked to run it, raw.
    pub command: String,
    /// The signals the hook's general verdict charged, each once, sorted.
    pub hook_signals: Vec<String>,
    /// An argument of the command came from an earlier tool result.
    pub tainted: bool,
    /// Always [`Verdict::Review`]: the hook asks about nothing else.
    pub hook_verdict: Verdict,
    /// Always [`RuleLayer::General`].
    pub hook_layer: RuleLayer,
}

impl InstanceDecideRequest {
    /// Whether every field holds what the contract lets it hold.
    pub fn is_valid(&self) -> bool {
        self.v == INSTANCE_DECIDE_VERSION
            && is_instance_id(&self.instance_id)
            && self
                .claimed_agent_type
                .as_deref()
                .is_none_or(is_agent_label)
            && self.session_id.as_deref().is_none_or(is_session_label)
            && !self.command.is_empty()
            && self.hook_signals.len() <= MAX_HOOK_SIGNALS
            && self.hook_signals.iter().all(|s| is_hook_signal(s))
            && self.hook_signals.windows(2).all(|pair| pair[0] < pair[1])
            && self.hook_verdict == Verdict::Review
            && self.hook_layer == RuleLayer::General
    }
}

/// PURE. The request a hook sends about one command its general rules sent
/// to review, or `None` when `instance_id` is not an id or the command is
/// empty.
///
/// `claimed_agent_type` is sent only when it is an agent label, and
/// `session_id` only when it has the shape of [`is_session_label`]; either is
/// `null` otherwise. Of `charged`, only the names [`is_hook_signal`] accepts
/// are sent, each once, sorted, at most [`MAX_HOOK_SIGNALS`].
pub fn instance_decide_request(
    instance_id: &str,
    claimed_agent_type: Option<&str>,
    session_id: Option<&str>,
    command: &str,
    charged: &[&str],
    tainted: bool,
) -> Option<InstanceDecideRequest> {
    if !is_instance_id(instance_id) || command.is_empty() {
        return None;
    }
    let signals: std::collections::BTreeSet<&str> = charged
        .iter()
        .copied()
        .filter(|name| is_hook_signal(name))
        .collect();
    Some(InstanceDecideRequest {
        v: INSTANCE_DECIDE_VERSION,
        instance_id: instance_id.to_string(),
        claimed_agent_type: claimed_agent_type
            .filter(|label| is_agent_label(label))
            .map(str::to_string),
        session_id: session_id
            .filter(|session| is_session_label(session))
            .map(str::to_string),
        command: command.to_string(),
        hook_signals: signals
            .into_iter()
            .take(MAX_HOOK_SIGNALS)
            .map(str::to_string)
            .collect(),
        tainted,
        hook_verdict: Verdict::Review,
        hook_layer: RuleLayer::General,
    })
}

/// The body of a 200 from [`INSTANCE_DECIDE_ROUTE`]. Every field is required
/// (a `null` where it may be one) and none other is accepted
/// (`deny_unknown_fields`).
///
/// ```json
/// {"v":1,"instance_id":"<id>","agent_type":"claude-code","trust":"confined",
///  "trust_source":"host","verdict":"allow","deciding_layer":"agent_type",
///  "profile":"claude-code","decision_id":"<32 hex>","withheld":null,
///  "signals_mismatch":false,"conflict":false,"incident_id":null}
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceDecideAnswer {
    /// [`INSTANCE_DECIDE_VERSION`].
    pub v: u32,
    /// The instance the host answered for.
    pub instance_id: String,
    /// The agent type the host holds for the instance.
    #[serde(deserialize_with = "nullable")]
    pub agent_type: Option<String>,
    /// The host's word for the instance.
    pub trust: Trust,
    /// Always [`HOST_TRUST_SOURCE`].
    pub trust_source: String,
    /// The host's verdict on the command.
    pub verdict: Verdict,
    /// The layer that made the host's verdict.
    pub deciding_layer: RuleLayer,
    /// The profile, when a per-agent layer decided.
    #[serde(deserialize_with = "nullable")]
    pub profile: Option<String>,
    /// The host's key for this decision ([`is_decision_id`]).
    pub decision_id: String,
    /// `null` only when a relaxation applied; otherwise a word
    /// ([`is_withheld_word`]) the hook records without reading it.
    #[serde(deserialize_with = "nullable")]
    pub withheld: Option<String>,
    /// The host read other signals than the hook sent. Only recorded.
    pub signals_mismatch: bool,
    /// The host found the request in conflict with what it holds.
    pub conflict: bool,
    /// The incident the host opened about it, if any.
    #[serde(deserialize_with = "nullable")]
    pub incident_id: Option<String>,
}

impl InstanceDecideAnswer {
    /// Whether the host let a relaxation apply: it says `confined` and
    /// withheld nothing. The only case in which the hook decides at
    /// `confined`.
    pub fn relaxes(&self) -> bool {
        self.trust == Trust::Confined && self.withheld.is_none()
    }
}

/// What the hook makes of a 200 from [`INSTANCE_DECIDE_ROUTE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostAnswer {
    /// The contract's answer, about this instance.
    Answer(InstanceDecideAnswer),
    /// Anything else: the hook decides as it would have without asking, and
    /// records [`HOST_ANSWER_INVALID`].
    Withheld,
}

/// PURE. Read the body of a 200 from [`INSTANCE_DECIDE_ROUTE`], for the hook
/// of `own_instance_id`. Only an answer of exactly the contract's shape
/// counts: no field missing, none more, `v` 1, the hook's own instance,
/// `trust_source` `host`, a decision id, and every word of the shape its
/// field allows. Everything else is [`HostAnswer::Withheld`].
pub fn read_host_answer(bytes: &[u8], own_instance_id: &str) -> HostAnswer {
    if bytes.len() > MAX_INSTANCE_ANSWER_BYTES {
        return HostAnswer::Withheld;
    }
    let Ok(answer) = serde_json::from_slice::<InstanceDecideAnswer>(bytes) else {
        return HostAnswer::Withheld;
    };
    let sound = answer.v == INSTANCE_DECIDE_VERSION
        && is_instance_id(own_instance_id)
        && answer.instance_id == own_instance_id
        && answer.trust_source == HOST_TRUST_SOURCE
        && is_decision_id(&answer.decision_id)
        && answer.agent_type.as_deref().is_none_or(is_agent_label)
        && answer.profile.as_deref().is_none_or(is_agent_label)
        && answer.withheld.as_deref().is_none_or(is_withheld_word)
        && answer.incident_id.as_deref().is_none_or(|id| {
            !id.is_empty() && id.len() <= 256 && !id.chars().any(char::is_control)
        });
    if sound {
        HostAnswer::Answer(answer)
    } else {
        HostAnswer::Withheld
    }
}

// ---------------------------------------------------------------------------
// The two axes
// ---------------------------------------------------------------------------

/// How we know which agent this is. Ordered: `Declared < Observed < Confined`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Trust {
    /// The agent, or a setting it can edit, says so.
    Declared,
    /// Something outside the agent's control saw the process and who started it.
    Observed,
    /// It runs inside a boundary it cannot leave, built by a trusted launcher.
    /// A witness outside the agent says so: no reading from inside the jail
    /// ([`judge_trust_in_jail`]) reaches this level.
    Confined,
}

impl Trust {
    pub fn as_str(self) -> &'static str {
        match self {
            Trust::Declared => "declared",
            Trust::Observed => "observed",
            Trust::Confined => "confined",
        }
    }
}

/// What the operator decided about an instance or a type of agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lifecycle {
    /// Seen, nobody decided.
    Discovered,
    /// The operator accepted it. Says nothing about trust.
    Approved,
    /// No new actions. History stays.
    Revoked,
}

impl Lifecycle {
    pub fn as_str(self) -> &'static str {
        match self {
            Lifecycle::Discovered => "discovered",
            Lifecycle::Approved => "approved",
            Lifecycle::Revoked => "revoked",
        }
    }
}

// ---------------------------------------------------------------------------
// The launch record
// ---------------------------------------------------------------------------

/// The newest schema number this build writes. It writes the newest only when
/// a record needs a field that version added (schema 2: `jail.userns_closed`);
/// every other record is [`LAUNCH_SCHEMA_V1`], byte for byte what an earlier
/// build wrote.
pub const LAUNCH_SCHEMA: u32 = 2;

/// The first schema: the field set of a record with nothing added.
pub const LAUNCH_SCHEMA_V1: u32 = 1;

/// The schema numbers this build reads: its own and the one before. The golden
/// test for version 1 keeps proving the old one still parses.
pub const READABLE_SCHEMAS: &[u32] = &[1, 2];

/// The largest record read. A record is a few hundred bytes; anything near this
/// is not one, and a reader that took more would let a writer cost it memory.
pub const MAX_RECORD_BYTES: usize = 16 * 1024;

/// The length of an instance id: 16 bytes in lowercase hex.
pub const INSTANCE_ID_LEN: usize = 32;
const MAX_LABEL_LEN: usize = 64;
const MAX_PROJECT_CHARS: usize = 120;
const MAX_VERSION_LEN: usize = 64;
const MAX_UNIT_LEN: usize = 255;
const MAX_PATH_LEN: usize = 4096;

/// How the agent's hook behaves in the jail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LaunchMode {
    Monitor,
    Enforce,
    BlockReview,
}

/// What built the jail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum JailBackend {
    /// Linux bubblewrap: has a PID namespace of its own.
    Bwrap,
    /// macOS sandbox-exec: a profile, no PID namespace.
    SandboxExec,
}

/// The program that launched the instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Launcher {
    /// Absolute path of the launcher binary as the launcher resolved it.
    pub path: String,
    pub version: String,
    /// The launcher binary is a file owned by root that its user cannot write.
    /// A per-user install (writable by the user's own programs) is `false`:
    /// anything the user runs could have replaced it.
    pub root_owned: bool,
}

/// The jail process, as the launcher saw it right after spawning it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Jail {
    pub backend: JailBackend,
    /// The pid on its own is never an identity: it is meaningful only together
    /// with `start_ticks`.
    pub pid: u32,
    /// Start time of `pid` in clock ticks since boot (field 22 of
    /// `/proc/<pid>/stat`). `0` means it was not read, which is not valid.
    pub start_ticks: u64,
    /// Inode of the jail's PID namespace. `0` when the backend has none.
    pub pid_ns: u64,
    /// Inode of the jail's mount namespace, the one its root is built in.
    /// `0` when the backend has none. A process in the jail that sees another
    /// mount namespace sees a filesystem the launcher did not build.
    pub mnt_ns: u64,
    /// Schema 2 only, and then always `true`: the jail was started so that its
    /// programs cannot make user namespaces of their own. A fact about how the
    /// jail was built, which the agent can read and forge like the rest of the
    /// record; it never raises trust ([`judge_trust_in_jail`] does not read it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userns_closed: Option<bool>,
}

/// A dedicated scope the jail was in, as the launcher read it from the kernel
/// (`/proc/<jail pid>/cgroup`) before the jail started.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    /// Always [`scope_unit_name`] of the record's instance.
    pub unit: String,
    pub cgroup_path: String,
}

/// The scopes of an instance. At least one is present, or the record carries
/// no `scope` at all.
///
/// * `user`: made by the user's own service manager around the jail. It names
///   the instance for whoever joins events to it, and inside the jail there is
///   no way out of it; outside the jail, any program of the same user can move
///   a process out of it. A label and a join key, never a guard boundary.
/// * `system`: made by root under the system slice. The user cannot create it,
///   move a process into it or out of it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scopes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<Scope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<Scope>,
}

impl Scopes {
    pub fn is_empty(&self) -> bool {
        self.user.is_none() && self.system.is_none()
    }
}

/// What the launcher knows about an instance it started, written by the
/// launcher outside the jail and shown read-only inside it.
///
/// No secrets: no environment, no argument vector, no token, no key. The
/// project is a folder NAME, never a path.
///
/// Unknown fields are refused (`deny_unknown_fields`) and so are duplicated
/// ones: the same schema number means the same field set, and a change to the
/// set bumps the number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchRecord {
    pub schema: u32,
    pub instance_id: String,
    pub agent_type: String,
    pub launcher: Launcher,
    pub uid: u32,
    /// The folder the agent works in, as a BASENAME.
    pub project: String,
    pub mode: LaunchMode,
    pub started_at: DateTime<Utc>,
    pub jail: Jail,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scopes>,
}

/// Why bytes were not accepted as a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    TooLarge,
    /// Not JSON, a wrong type, a missing, unknown or duplicated field.
    Malformed(String),
    /// No readable `schema` number.
    NoSchema,
    /// Written by a newer build than this one: its fields cannot be trusted to
    /// mean what this build thinks they mean.
    NewerSchema(u64),
    /// A schema number this build never wrote.
    UnsupportedSchema(u64),
    /// Well-formed, but a value is outside what the field may hold.
    Invalid(&'static str),
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordError::TooLarge => {
                write!(f, "launch record is larger than {MAX_RECORD_BYTES} bytes")
            }
            RecordError::Malformed(why) => write!(f, "launch record is malformed: {why}"),
            RecordError::NoSchema => write!(f, "launch record has no schema number"),
            RecordError::NewerSchema(n) => write!(
                f,
                "launch record has schema {n}, newer than this build reads"
            ),
            RecordError::UnsupportedSchema(n) => {
                write!(f, "launch record has unsupported schema {n}")
            }
            RecordError::Invalid(why) => write!(f, "launch record is invalid: {why}"),
        }
    }
}

impl std::error::Error for RecordError {}

/// Read a record from bytes.
///
/// A reader at version N reads N and N-1: the schema number picks the decoder,
/// and a number this build does not know is refused rather than guessed, so an
/// older reader never reads a newer record as if it were its own.
pub fn parse_launch_record(bytes: &[u8]) -> Result<LaunchRecord, RecordError> {
    parse_launch_record_as(bytes, READABLE_SCHEMAS, LAUNCH_SCHEMA)
}

/// [`parse_launch_record`] for a reader that reads `readable` and whose newest
/// schema is `newest`. The build's own reader is `(READABLE_SCHEMAS,
/// LAUNCH_SCHEMA)`; a test passes an older build's pair to prove that build
/// refuses a newer record instead of reading it as its own.
fn parse_launch_record_as(
    bytes: &[u8],
    readable: &[u32],
    newest: u32,
) -> Result<LaunchRecord, RecordError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(RecordError::TooLarge);
    }
    #[derive(Deserialize)]
    struct Probe {
        schema: Option<u64>,
    }
    let probe: Probe =
        serde_json::from_slice(bytes).map_err(|e| RecordError::Malformed(e.to_string()))?;
    let schema = probe.schema.ok_or(RecordError::NoSchema)?;
    let known = u32::try_from(schema)
        .ok()
        .is_some_and(|n| readable.contains(&n));
    if !known {
        return Err(if schema > u64::from(newest) {
            RecordError::NewerSchema(schema)
        } else {
            RecordError::UnsupportedSchema(schema)
        });
    }
    // One decoder serves every readable schema; `validate` holds each to its
    // own field set.
    let record: LaunchRecord =
        serde_json::from_slice(bytes).map_err(|e| RecordError::Malformed(e.to_string()))?;
    record.validate()?;
    Ok(record)
}

impl LaunchRecord {
    /// Whether every value is inside what its field may hold.
    pub fn validate(&self) -> Result<(), RecordError> {
        // The same number means the same field set. Schema 1 has no
        // `userns_closed`; schema 2 exists to carry it, and only as `true`.
        match self.schema {
            LAUNCH_SCHEMA_V1 => {
                if self.jail.userns_closed.is_some() {
                    return Err(RecordError::Malformed(
                        "jail.userns_closed is not a field of schema 1".to_string(),
                    ));
                }
            }
            2 => {
                if self.jail.userns_closed != Some(true) {
                    return Err(RecordError::Invalid(
                        "schema 2 carries jail.userns_closed, and only as true",
                    ));
                }
            }
            _ => {
                return Err(RecordError::Invalid("schema is not one this build reads"));
            }
        }
        if !is_instance_id(&self.instance_id) {
            return Err(RecordError::Invalid("instance_id"));
        }
        if !is_agent_label(&self.agent_type) {
            return Err(RecordError::Invalid("agent_type"));
        }
        if !is_project_name(&self.project) {
            return Err(RecordError::Invalid("project"));
        }
        if !is_absolute_path(&self.launcher.path) {
            return Err(RecordError::Invalid("launcher.path"));
        }
        if !is_version(&self.launcher.version) {
            return Err(RecordError::Invalid("launcher.version"));
        }
        if self.jail.pid == 0 {
            return Err(RecordError::Invalid("jail.pid"));
        }
        if self.jail.start_ticks == 0 {
            return Err(RecordError::Invalid("jail.start_ticks"));
        }
        match self.jail.backend {
            JailBackend::Bwrap if self.jail.pid_ns == 0 => {
                return Err(RecordError::Invalid(
                    "jail.pid_ns is missing for a PID namespace backend",
                ));
            }
            JailBackend::SandboxExec if self.jail.pid_ns != 0 => {
                return Err(RecordError::Invalid(
                    "jail.pid_ns set for a backend with no PID namespace",
                ));
            }
            _ => {}
        }
        match self.jail.backend {
            JailBackend::Bwrap if self.jail.mnt_ns == 0 => {
                return Err(RecordError::Invalid(
                    "jail.mnt_ns is missing for a namespace backend",
                ));
            }
            JailBackend::SandboxExec if self.jail.mnt_ns != 0 => {
                return Err(RecordError::Invalid(
                    "jail.mnt_ns set for a backend with no namespace",
                ));
            }
            _ => {}
        }
        if let Some(scopes) = &self.scope {
            self.validate_scopes(scopes)?;
        }
        Ok(())
    }

    /// A scope belongs to THIS instance: its unit is the instance's name and
    /// its cgroup is where that unit lives. A record cannot borrow another
    /// instance's scope, or call a user scope a system one.
    fn validate_scopes(&self, scopes: &Scopes) -> Result<(), RecordError> {
        if scopes.is_empty() {
            return Err(RecordError::Invalid("scope has neither user nor system"));
        }
        let unit = scope_unit_name(&self.instance_id).ok_or(RecordError::Invalid("instance_id"))?;
        if let Some(user) = &scopes.user {
            if !is_unit_name(&user.unit) || user.unit != unit {
                return Err(RecordError::Invalid("scope.user.unit"));
            }
            if !is_user_scope_cgroup(&user.cgroup_path, &unit, self.uid) {
                return Err(RecordError::Invalid("scope.user.cgroup_path"));
            }
        }
        if let Some(system) = &scopes.system {
            if !is_unit_name(&system.unit) || system.unit != unit {
                return Err(RecordError::Invalid("scope.system.unit"));
            }
            if system.cgroup_path != system_scope_cgroup(&unit) {
                return Err(RecordError::Invalid("scope.system.cgroup_path"));
            }
        }
        Ok(())
    }
}

/// Exactly [`INSTANCE_ID_LEN`] lowercase hex characters: the only shape the
/// launcher makes (16 random bytes), and the one every reader and the
/// dashboard accept. It becomes a file name and a unit name, so no dot, slash,
/// dash or case.
pub fn is_instance_id(id: &str) -> bool {
    id.len() == INSTANCE_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The same shape as the agent id a decision records: lowercase, digits, `-`
/// and `_`, up to 64 bytes. The rule a `claimed_agent_type` meets
/// ([`InstanceDecideRequest`]).
pub fn is_agent_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_LABEL_LEN
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// The same shape as the project a decision records: a basename.
fn is_project_name(project: &str) -> bool {
    let count = project.chars().count();
    count > 0
        && count <= MAX_PROJECT_CHARS
        && !project.contains(['/', '\\'])
        && project != "."
        && project != ".."
        && !project.chars().any(char::is_control)
}

fn is_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= MAX_VERSION_LEN
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-' | b'_'))
}

/// A systemd unit name: letters, digits and `: _ . \ - @`.
fn is_unit_name(unit: &str) -> bool {
    !unit.is_empty()
        && unit.len() <= MAX_UNIT_LEN
        && unit.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b':' | b'_' | b'.' | b'\\' | b'-' | b'@')
        })
}

/// Absolute, bounded, no control character, no `..` step.
fn is_absolute_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= MAX_PATH_LEN
        && !path.chars().any(char::is_control)
        && !Path::new(path)
            .components()
            .any(|c| matches!(c, Component::ParentDir))
}

// ---------------------------------------------------------------------------
// Trust inside the jail
// ---------------------------------------------------------------------------

/// The inode the kernel gives the initial PID namespace, `pid:[4026531836]`.
/// A record that names it describes no jail: the namespace is the host's own.
pub const INITIAL_PID_NS_INODE: u64 = 0xEFFF_FFFC;

/// What the hook found at [`JAIL_RECORD_PATH`].
#[derive(Debug, Clone, Copy)]
pub enum RecordRead<'a> {
    /// There is no file there.
    Absent,
    /// There is a file and it could not be used: unreadable, too large, not a
    /// record, a schema this build does not read.
    Unreadable,
    /// A record that parsed.
    Present {
        record: &'a LaunchRecord,
        /// The file is on a read-only mount. A record the agent could write is
        /// whatever the agent wrote.
        read_only: bool,
    },
}

/// The facts [`judge_trust_in_jail`] decides from, all read by the caller.
#[derive(Debug, Clone, Copy)]
pub struct InJailFacts<'a> {
    pub record: RecordRead<'a>,
    /// Inode of the hook's own PID namespace (`/proc/self/ns/pid`), `None` if it
    /// could not be read.
    pub own_pid_ns: Option<u64>,
    /// Inode of the hook's own mount namespace (`/proc/self/ns/mnt`), `None` if
    /// it could not be read.
    pub own_mnt_ns: Option<u64>,
}

/// Why [`judge_trust_in_jail`] gave the level it gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// Same namespaces as the record, read-only record, trusted launcher, a
    /// scope: everything a reading from inside the jail can check holds. The
    /// level it earns is still `observed` (see [`judge_trust_in_jail`], row
    /// 10); the code names what was found, not what it proves.
    ConfinedByNamespace,
    /// Same namespace as the record, but the launcher is a file its user could
    /// have replaced (a per-user install).
    LauncherNotTrusted,
    /// Same namespace, trusted launcher, but the jail was not in a dedicated
    /// scope: a namespace the agent cannot leave, a cgroup nobody named.
    NoScope,
    NoRecord,
    RecordUnreadable,
    RecordWritable,
    /// The backend has no PID namespace to compare (macOS).
    NoNamespaceOnBackend,
    /// The record names the host's own namespace, so it describes no jail.
    HostNamespaceRecorded,
    OwnNamespaceUnreadable,
    NamespaceMismatch,
    OwnMountNamespaceUnreadable,
    /// Same PID namespace, another mount namespace: the process sees a
    /// filesystem the launcher did not build. A program in the jail that makes
    /// a mount namespace of its own, for whatever reason, is here too: what it
    /// sees at the record's place is no longer the launcher's word.
    MountNamespaceMismatch,
    /// The record names another kind of agent than the hook line was wired for.
    AgentMismatch,
    /// Neither the hook line nor the launcher named the agent the hook serves,
    /// so nothing holds the record's type to the hook that reads it.
    AgentNotNamed,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::ConfinedByNamespace => "confined_by_namespace",
            Reason::LauncherNotTrusted => "launcher_not_trusted",
            Reason::NoScope => "no_scope",
            Reason::NoRecord => "no_record",
            Reason::RecordUnreadable => "record_unreadable",
            Reason::RecordWritable => "record_writable",
            Reason::NoNamespaceOnBackend => "no_namespace_on_backend",
            Reason::HostNamespaceRecorded => "host_namespace_recorded",
            Reason::OwnNamespaceUnreadable => "own_namespace_unreadable",
            Reason::NamespaceMismatch => "namespace_mismatch",
            Reason::OwnMountNamespaceUnreadable => "own_mount_namespace_unreadable",
            Reason::MountNamespaceMismatch => "mount_namespace_mismatch",
            Reason::AgentMismatch => "agent_mismatch",
            Reason::AgentNotNamed => "agent_not_named",
        }
    }
}

/// The trust a hook can claim for itself, from inside a jail.
///
/// The rows are checked in this order, the first that holds decides:
///
/// | # | Fact | Trust | Reason |
/// |---|------|-------|--------|
/// | 1 | no record | declared | `NoRecord` |
/// | 2 | record could not be used, or fails [`LaunchRecord::validate`] | declared | `RecordUnreadable` |
/// | 3 | record not on a read-only mount | declared | `RecordWritable` |
/// | 4 | backend has no PID namespace | declared | `NoNamespaceOnBackend` |
/// | 5 | record names the initial PID namespace | declared | `HostNamespaceRecorded` |
/// | 6 | own namespace unreadable | declared | `OwnNamespaceUnreadable` |
/// | 7 | own namespace is not the recorded one | declared | `NamespaceMismatch` |
/// | 7a | own mount namespace unreadable | declared | `OwnMountNamespaceUnreadable` |
/// | 7b | own mount namespace is not the recorded one | declared | `MountNamespaceMismatch` |
/// | 8 | same namespaces, launcher not root-owned | observed | `LauncherNotTrusted` |
/// | 9 | same namespaces, launcher root-owned, no scope recorded | observed | `NoScope` |
/// | 10 | same namespaces, launcher root-owned, a scope recorded | observed | `ConfinedByNamespace` |
///
/// No row reaches `confined`. Why each row is the way it is:
///
/// * 3: the namespace is readable by the agent, so a record it can write is a
///   record it can make say anything.
/// * 5: a launcher bug or a forged record naming the host's namespace would
///   otherwise make every process on the machine "match".
/// * 7: a record copied into a place the launcher never put it describes
///   another process's jail.
/// * 7a, 7b: the record sits on a mount of the jail's root. A process in a
///   mount namespace other than the jail's sees whatever that namespace put
///   there, even with the PID namespace unchanged; a child that legitimately
///   makes its own (a nested sandbox, a build tool) is in that case too, and
///   is reported as not the launcher's jail rather than guessed to be.
/// * 8 is a ceiling, not a bonus: with a launcher the user's own programs can
///   replace, the record proves where this process runs and not who built the
///   boundary. Nothing here reaches `confined` from a per-user install.
/// * 9: `confined` is a PID namespace AND a cgroup the agent cannot leave. A
///   launch on a host with no user service manager runs with no dedicated
///   scope, and its launcher says on screen that the instance is `observed` at
///   most; this row is what makes that sentence true.
/// * 10 is a ceiling too. Every fact the rows compare is one the agent's own
///   process can produce: on a host where an unprivileged process may make a
///   user namespace, the agent can make a mount namespace of its own, put a
///   record of its own on a read-only mount there (naming its own namespaces,
///   a root-owned launcher, a scope and any type of agent), and run a hook in
///   it. That hook sees exactly what a hook in the launcher's jail sees. So a
///   reading from inside the jail is never more than `observed`, and
///   `observed` unlocks no per-agent relaxation ([`decide`]): what is
///   relaxed for `confined` needs a witness outside the agent, never this
///   reading.
///
/// This is the in-jail view and only that. It reads no `/proc` and takes no
/// word from the environment; a stronger level needs a witness outside the
/// agent.
pub fn judge_trust_in_jail(facts: InJailFacts<'_>) -> (Trust, Reason) {
    let (record, read_only) = match facts.record {
        RecordRead::Absent => return (Trust::Declared, Reason::NoRecord),
        RecordRead::Unreadable => return (Trust::Declared, Reason::RecordUnreadable),
        RecordRead::Present { record, read_only } => (record, read_only),
    };
    if record.validate().is_err() {
        return (Trust::Declared, Reason::RecordUnreadable);
    }
    if !read_only {
        return (Trust::Declared, Reason::RecordWritable);
    }
    if record.jail.backend != JailBackend::Bwrap {
        return (Trust::Declared, Reason::NoNamespaceOnBackend);
    }
    if record.jail.pid_ns == INITIAL_PID_NS_INODE {
        return (Trust::Declared, Reason::HostNamespaceRecorded);
    }
    let Some(own) = facts.own_pid_ns else {
        return (Trust::Declared, Reason::OwnNamespaceUnreadable);
    };
    if own != record.jail.pid_ns {
        return (Trust::Declared, Reason::NamespaceMismatch);
    }
    let Some(own_mnt) = facts.own_mnt_ns else {
        return (Trust::Declared, Reason::OwnMountNamespaceUnreadable);
    };
    if own_mnt != record.jail.mnt_ns {
        return (Trust::Declared, Reason::MountNamespaceMismatch);
    }
    if !record.launcher.root_owned {
        return (Trust::Observed, Reason::LauncherNotTrusted);
    }
    if record.scope.as_ref().is_none_or(Scopes::is_empty) {
        return (Trust::Observed, Reason::NoScope);
    }
    (Trust::Observed, Reason::ConfinedByNamespace)
}

/// Hold a level to the agent the hook line was wired for.
///
/// The hook (its line's `--agent <id>`, or the launcher's word for the agent
/// it started) and the record both name a kind of agent. When they name two,
/// one of the two is not what it says, and neither is evidence: the level drops
/// to `declared` with [`Reason::AgentMismatch`]. When the hook names none,
/// nothing ties the record's type to this hook, and the level drops to
/// `declared` with [`Reason::AgentNotNamed`]. A level that is already
/// `declared` keeps its first reason.
pub fn judge_agent_claim(
    judged: (Trust, Reason),
    record_agent: &str,
    hook_agent: Option<&str>,
) -> (Trust, Reason) {
    if judged.0 == Trust::Declared {
        return judged;
    }
    match hook_agent {
        Some(wired) if wired == record_agent => judged,
        Some(_) => (Trust::Declared, Reason::AgentMismatch),
        None => (Trust::Declared, Reason::AgentNotNamed),
    }
}

// ---------------------------------------------------------------------------
// Rules in layers
// ---------------------------------------------------------------------------

/// The four layers, widest first. Also the order they are reported in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleLayer {
    /// Product rules, the same everywhere, relaxed by nothing.
    Hard,
    /// The host's or organization's rules, for every agent.
    General,
    /// A profile for a type of agent.
    AgentType,
    /// An exception for one instance.
    Instance,
}

impl RuleLayer {
    pub fn as_str(self) -> &'static str {
        match self {
            RuleLayer::Hard => "hard",
            RuleLayer::General => "general",
            RuleLayer::AgentType => "agent_type",
            RuleLayer::Instance => "instance",
        }
    }
}

/// The outcome of screening, spelled like the engine's `recommendation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Review,
    Deny,
}

/// What a profile or an exception can say about an action: let it through, or
/// refuse it. Asking is the general layer's word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LayerRule {
    Allow,
    Deny,
}

/// What each layer says about one action. The general layer always has an
/// answer (the screening engine's verdict); the others only when a rule of
/// theirs matched. One slot per layer, so a layer cannot speak twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layers {
    /// A hard rule refuses it. See [`is_hard_signal`].
    pub hard_refused: bool,
    pub general: Verdict,
    pub agent_type: Option<LayerRule>,
    pub instance: Option<LayerRule>,
}

/// The decision and the layer that made it, for the screen to say why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub verdict: Verdict,
    pub deciding_layer: RuleLayer,
}

/// Combine the layers.
///
/// 1. A hard refusal wins over everything.
/// 2. Then any `deny`, from any layer and at any trust level. When more than one
///    denies, the widest is named (general, then type, then instance). A deny
///    never loosens anything, so there is nothing to gate.
/// 3. Then an `allow`, the narrowest layer first (instance, then type), and
///    only when `trust` is [`Trust::Confined`]. For an instance that is only
///    `declared` or `observed`, the profile and the exception do not exist and
///    the general verdict stands.
/// 4. Otherwise the general verdict.
///
/// A general `deny` is not relaxed by a narrower `allow`: step 2 comes first.
/// What a profile can relax is a general `review`.
pub fn decide(layers: Layers, trust: Trust) -> Decision {
    if layers.hard_refused {
        return Decision {
            verdict: Verdict::Deny,
            deciding_layer: RuleLayer::Hard,
        };
    }
    if layers.general == Verdict::Deny {
        return Decision {
            verdict: Verdict::Deny,
            deciding_layer: RuleLayer::General,
        };
    }
    if layers.agent_type == Some(LayerRule::Deny) {
        return Decision {
            verdict: Verdict::Deny,
            deciding_layer: RuleLayer::AgentType,
        };
    }
    if layers.instance == Some(LayerRule::Deny) {
        return Decision {
            verdict: Verdict::Deny,
            deciding_layer: RuleLayer::Instance,
        };
    }
    if trust == Trust::Confined {
        if layers.instance == Some(LayerRule::Allow) {
            return Decision {
                verdict: Verdict::Allow,
                deciding_layer: RuleLayer::Instance,
            };
        }
        if layers.agent_type == Some(LayerRule::Allow) {
            return Decision {
                verdict: Verdict::Allow,
                deciding_layer: RuleLayer::AgentType,
            };
        }
    }
    Decision {
        verdict: layers.general,
        deciding_layer: RuleLayer::General,
    }
}

// ---------------------------------------------------------------------------
// The hard layer
// ---------------------------------------------------------------------------

/// Signals the hard layer refuses besides [`AGENT_REVIEW_FLOOR`]:
///
/// * `guard_self_disable`: switching the guard off, or writing into its own
///   configuration;
/// * `security_tooling_tamper`: stopping, removing or truncating the product;
/// * `privileged_file_write`: a file tool changing a privileged place;
/// * `sensitive_credential_read`: reading `~/.ssh`, `~/.aws`, `~/.gnupg` and
///   the like.
///
/// The LLM key has no signal of its own (the jail hides the file), so it joins
/// the hard layer where a profile is applied, as a path rule
/// ([`crate::threats::names_guard_llm_key`], used by [`crate::profiles`]).
const EXTRA_HARD_SIGNALS: &[&str] = &[
    "guard_self_disable",
    "security_tooling_tamper",
    "privileged_file_write",
    "sensitive_credential_read",
];

/// Whether a signal name is a hard rule. The floor is read from the constant the
/// benchmark measures, not copied, so the two cannot drift apart.
pub fn is_hard_signal(signal: &str) -> bool {
    AGENT_REVIEW_FLOOR.contains(&signal) || EXTRA_HARD_SIGNALS.contains(&signal)
}

/// Whether an analysis carries a hard signal. Only a CHARGED signal counts: a
/// subsumed duplicate is scored 0 and must not raise the floor on its own, the
/// same rule `blocks_for_agent` applies.
pub fn hits_hard_layer(analysis: &CommandAnalysis) -> bool {
    analysis
        .signals
        .iter()
        .any(|s| s.score > 0 && is_hard_signal(&s.signal))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    // -- the two axes -------------------------------------------------------

    #[test]
    fn trust_is_ordered_and_spelled_stably() {
        assert!(Trust::Declared < Trust::Observed && Trust::Observed < Trust::Confined);
        for (trust, word) in [
            (Trust::Declared, "declared"),
            (Trust::Observed, "observed"),
            (Trust::Confined, "confined"),
        ] {
            assert_eq!(serde_json::to_value(trust).unwrap(), json!(word));
            assert_eq!(serde_json::from_value::<Trust>(json!(word)).unwrap(), trust);
            assert_eq!(trust.as_str(), word);
        }
    }

    /// The word held back for cryptographic proof cannot be read off a wire.
    #[test]
    fn the_reserved_level_does_not_deserialize() {
        for word in ["authenticated", "Confined", "root", ""] {
            assert!(
                serde_json::from_value::<Trust>(json!(word)).is_err(),
                "{word}"
            );
        }
    }

    #[test]
    fn lifecycle_is_spelled_stably_and_is_not_trust() {
        for (state, word) in [
            (Lifecycle::Discovered, "discovered"),
            (Lifecycle::Approved, "approved"),
            (Lifecycle::Revoked, "revoked"),
        ] {
            assert_eq!(serde_json::to_value(state).unwrap(), json!(word));
            assert_eq!(
                serde_json::from_value::<Lifecycle>(json!(word)).unwrap(),
                state
            );
            assert_eq!(state.as_str(), word);
        }
        // The two axes share no word.
        for trust in ["declared", "observed", "confined"] {
            assert!(serde_json::from_value::<Lifecycle>(json!(trust)).is_err());
        }
    }

    // -- the launch record --------------------------------------------------

    /// A version 1 record exactly as a launcher writes it. This text never
    /// changes: it is what a reader at any later version must still parse
    /// (N reads N-1).
    const GOLDEN_V1: &str = r#"{
  "schema": 1,
  "instance_id": "7f3a9c1e42b84d0e9a6c5f1b2d3e4a59",
  "agent_type": "claude-code",
  "launcher": { "path": "/usr/local/bin/innerwarden", "version": "1.6.0", "root_owned": true },
  "uid": 1000,
  "project": "my-app",
  "mode": "enforce",
  "started_at": "2026-10-16T09:30:00Z",
  "jail": { "backend": "bwrap", "pid": 48211, "start_ticks": 9120344, "pid_ns": 4026532871, "mnt_ns": 4026532869 },
  "scope": {
    "user": {
      "unit": "innerwarden-contain-7f3a9c1e42b84d0e9a6c5f1b2d3e4a59.scope",
      "cgroup_path": "/user.slice/user-1000.slice/user@1000.service/app.slice/innerwarden-contain-7f3a9c1e42b84d0e9a6c5f1b2d3e4a59.scope"
    },
    "system": {
      "unit": "innerwarden-contain-7f3a9c1e42b84d0e9a6c5f1b2d3e4a59.scope",
      "cgroup_path": "/system.slice/innerwarden-contain-7f3a9c1e42b84d0e9a6c5f1b2d3e4a59.scope"
    }
  }
}"#;

    fn golden() -> LaunchRecord {
        parse_launch_record(GOLDEN_V1.as_bytes()).expect("the golden v1 record parses")
    }

    fn golden_json() -> Value {
        serde_json::from_str(GOLDEN_V1).unwrap()
    }

    fn parse_value(value: &Value) -> Result<LaunchRecord, RecordError> {
        parse_launch_record(value.to_string().as_bytes())
    }

    /// A version 2 record exactly as a launcher writes it when it closed user
    /// namespaces in the jail: the version 1 field set plus `jail.userns_closed`.
    /// Like [`GOLDEN_V1`] this text never changes.
    const GOLDEN_V2: &str = r#"{
  "schema": 2,
  "instance_id": "7f3a9c1e42b84d0e9a6c5f1b2d3e4a59",
  "agent_type": "claude-code",
  "launcher": { "path": "/usr/local/bin/innerwarden", "version": "1.6.0", "root_owned": true },
  "uid": 1000,
  "project": "my-app",
  "mode": "enforce",
  "started_at": "2026-10-16T09:30:00Z",
  "jail": { "backend": "bwrap", "pid": 48211, "start_ticks": 9120344, "pid_ns": 4026532871, "mnt_ns": 4026532869, "userns_closed": true },
  "scope": {
    "user": {
      "unit": "innerwarden-contain-7f3a9c1e42b84d0e9a6c5f1b2d3e4a59.scope",
      "cgroup_path": "/user.slice/user-1000.slice/user@1000.service/app.slice/innerwarden-contain-7f3a9c1e42b84d0e9a6c5f1b2d3e4a59.scope"
    }
  }
}"#;

    fn golden_v2_json() -> Value {
        serde_json::from_str(GOLDEN_V2).unwrap()
    }

    #[test]
    fn the_golden_v2_record_parses_and_round_trips() {
        let record =
            parse_launch_record(GOLDEN_V2.as_bytes()).expect("the golden v2 record parses");
        assert_eq!(record.schema, 2);
        assert_eq!(record.jail.userns_closed, Some(true));
        assert_eq!(serde_json::to_value(&record).unwrap(), golden_v2_json());
        // And the version 1 golden still parses, with the field absent and
        // written back absent.
        let v1 = golden();
        assert_eq!(v1.schema, 1);
        assert_eq!(v1.jail.userns_closed, None);
        assert!(serde_json::to_value(&v1).unwrap()["jail"]
            .get("userns_closed")
            .is_none());
    }

    /// Schema 1 has no `userns_closed`: a version 1 record that carries it,
    /// true or false, is not a version 1 record.
    ///
    /// FAILS ON REVERT: drop the schema 1 arm of `validate` and the version 1
    /// record with the field parses.
    #[test]
    fn v1_with_userns_closed_is_refused() {
        for value in [json!(true), json!(false)] {
            let mut record = golden_json();
            record["jail"]["userns_closed"] = value;
            assert!(
                matches!(parse_value(&record), Err(RecordError::Malformed(_))),
                "{record}"
            );
        }
    }

    /// Schema 2 exists to carry the field, and only as `true`.
    ///
    /// FAILS ON REVERT: drop the schema 2 arm of `validate` and a version 2
    /// record with no field, or with `false`, parses.
    #[test]
    fn v2_without_userns_closed_true_is_refused() {
        let mut absent = golden_v2_json();
        absent["jail"]
            .as_object_mut()
            .unwrap()
            .remove("userns_closed");
        assert!(matches!(parse_value(&absent), Err(RecordError::Invalid(_))));
        let mut off = golden_v2_json();
        off["jail"]["userns_closed"] = json!(false);
        assert!(matches!(parse_value(&off), Err(RecordError::Invalid(_))));
        let mut null = golden_v2_json();
        null["jail"]["userns_closed"] = json!(null);
        assert!(matches!(parse_value(&null), Err(RecordError::Invalid(_))));
    }

    /// A reader of the previous build (reads `[1]`, writes 1) meets a version
    /// 2 record and refuses it as newer: it degrades to an unreadable record,
    /// never to a level above what it read.
    ///
    /// FAILS ON REVERT: let `parse_launch_record_as` ignore its `readable`
    /// list and the old reader reads the version 2 record.
    #[test]
    fn an_older_reader_refuses_a_v2_record() {
        assert_eq!(
            parse_launch_record_as(GOLDEN_V2.as_bytes(), &[1], 1),
            Err(RecordError::NewerSchema(2))
        );
        assert!(parse_launch_record_as(GOLDEN_V1.as_bytes(), &[1], 1).is_ok());
        assert!(
            parse_launch_record_as(GOLDEN_V2.as_bytes(), READABLE_SCHEMAS, LAUNCH_SCHEMA).is_ok()
        );
    }

    /// That user namespaces were closed is a fact the agent can write into a
    /// record of its own, so it moves nothing: the same facts judge the same
    /// with the field and without it, in every row a record reaches.
    ///
    /// FAILS ON REVERT: let `judge_trust_in_jail` return `confined` for a
    /// record that says `userns_closed` and this sees `confined`.
    #[test]
    fn userns_closed_never_raises_trust() {
        let without = golden();
        let mut with = golden();
        with.schema = 2;
        with.jail.userns_closed = Some(true);
        for read_only in [true, false] {
            for own in [Some(OWN_NS), Some(1), None] {
                assert_eq!(
                    judge_trust_in_jail(facts(&with, read_only, own)),
                    judge_trust_in_jail(facts(&without, read_only, own)),
                    "read_only={read_only} own={own:?}"
                );
            }
        }
        assert_eq!(
            judge_trust_in_jail(facts(&with, true, Some(OWN_NS))),
            (Trust::Observed, Reason::ConfinedByNamespace)
        );
        // A record forged by the agent, field and all, reads the same too.
        let forged = parse_launch_record(GOLDEN_V2.as_bytes()).unwrap();
        assert!(judge_trust_in_jail(facts(&forged, true, Some(OWN_NS))).0 < Trust::Confined);
    }

    #[test]
    fn the_golden_v1_record_parses_and_round_trips() {
        let record = golden();
        assert_eq!(record.agent_type, "claude-code");
        assert_eq!(record.jail.pid_ns, 4026532871);
        assert_eq!(record.jail.mnt_ns, 4026532869);
        assert!(record.launcher.root_owned);
        assert_eq!(serde_json::to_value(&record).unwrap(), golden_json());
    }

    /// A record without a scope is valid, and writes no `scope` key.
    #[test]
    fn a_record_without_a_scope_parses_and_writes_none() {
        let mut value = golden_json();
        value.as_object_mut().unwrap().remove("scope");
        let record = parse_value(&value).unwrap();
        assert!(record.scope.is_none());
        assert!(serde_json::to_value(&record)
            .unwrap()
            .get("scope")
            .is_none());
    }

    /// "No secrets": the field set is the contract. A field added without
    /// thought (an env map, an argv, a token) changes this list and fails here.
    #[test]
    fn the_record_carries_exactly_the_labels_and_facts_and_no_secret_field() {
        let value = serde_json::to_value(golden()).unwrap();
        let keys = |v: &Value| -> Vec<String> {
            let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
            k.sort();
            k
        };
        assert_eq!(
            keys(&value),
            [
                "agent_type",
                "instance_id",
                "jail",
                "launcher",
                "mode",
                "project",
                "schema",
                "scope",
                "started_at",
                "uid"
            ]
        );
        assert_eq!(keys(&value["launcher"]), ["path", "root_owned", "version"]);
        assert_eq!(
            keys(&value["jail"]),
            ["backend", "mnt_ns", "pid", "pid_ns", "start_ticks"]
        );
        assert_eq!(keys(&value["scope"]), ["system", "user"]);
        assert_eq!(keys(&value["scope"]["user"]), ["cgroup_path", "unit"]);
        assert_eq!(keys(&value["scope"]["system"]), ["cgroup_path", "unit"]);
        // And no trust field: the file cannot say what level it earns.
        for banned in ["trust", "confined", "level", "token", "env", "argv", "key"] {
            assert!(value.get(banned).is_none(), "{banned}");
        }
    }

    #[test]
    fn a_newer_schema_is_refused_not_guessed() {
        let mut value = golden_json();
        value["schema"] = json!(3);
        assert_eq!(parse_value(&value), Err(RecordError::NewerSchema(3)));
        value["schema"] = json!(4_000_000_000u64);
        assert_eq!(
            parse_value(&value),
            Err(RecordError::NewerSchema(4_000_000_000))
        );
        value["schema"] = json!(u64::MAX);
        assert_eq!(parse_value(&value), Err(RecordError::NewerSchema(u64::MAX)));
    }

    #[test]
    fn a_schema_this_build_never_wrote_is_refused() {
        let mut value = golden_json();
        value["schema"] = json!(0);
        assert_eq!(parse_value(&value), Err(RecordError::UnsupportedSchema(0)));
    }

    #[test]
    fn a_missing_or_mistyped_schema_is_refused() {
        let mut value = golden_json();
        value.as_object_mut().unwrap().remove("schema");
        assert_eq!(parse_value(&value), Err(RecordError::NoSchema));
        value["schema"] = json!("1");
        assert!(matches!(
            parse_value(&value),
            Err(RecordError::Malformed(_))
        ));
        value["schema"] = json!(-1);
        assert!(matches!(
            parse_value(&value),
            Err(RecordError::Malformed(_))
        ));
    }

    /// Same schema number, same field set: an extra field is not tolerated.
    #[test]
    fn an_unknown_field_is_refused_at_every_level() {
        for path in [
            vec![],
            vec!["launcher"],
            vec!["jail"],
            vec!["scope"],
            vec!["scope", "user"],
            vec!["scope", "system"],
        ] {
            let mut value = golden_json();
            let mut at = &mut value;
            for step in &path {
                at = &mut at[*step];
            }
            at["extra"] = json!(true);
            assert!(
                matches!(parse_value(&value), Err(RecordError::Malformed(_))),
                "an unknown field under {path:?} must be refused"
            );
        }
    }

    #[test]
    fn a_missing_field_is_refused() {
        for key in [
            "instance_id",
            "agent_type",
            "launcher",
            "uid",
            "project",
            "mode",
            "started_at",
            "jail",
        ] {
            let mut value = golden_json();
            value.as_object_mut().unwrap().remove(key);
            assert!(
                matches!(parse_value(&value), Err(RecordError::Malformed(_))),
                "{key}"
            );
        }
    }

    /// Two readers that disagree on which duplicate wins are a way to show one
    /// reader a record the other did not see. Refused.
    #[test]
    fn a_duplicated_key_is_refused() {
        let text = GOLDEN_V1.replacen(
            r#""pid_ns": 4026532871"#,
            r#""pid_ns": 1, "pid_ns": 4026532871"#,
            1,
        );
        assert_ne!(text, GOLDEN_V1);
        assert!(matches!(
            parse_launch_record(text.as_bytes()),
            Err(RecordError::Malformed(_))
        ));
    }

    #[test]
    fn a_record_over_the_size_limit_is_refused_before_it_is_parsed() {
        let mut bytes = vec![b' '; MAX_RECORD_BYTES + 1];
        bytes[0] = b'{';
        assert_eq!(parse_launch_record(&bytes), Err(RecordError::TooLarge));
        // At the limit it is parsed (and fails on content, not size).
        let at_limit = vec![b' '; MAX_RECORD_BYTES];
        assert!(matches!(
            parse_launch_record(&at_limit),
            Err(RecordError::Malformed(_))
        ));
    }

    #[test]
    fn what_is_not_json_is_refused() {
        for bytes in [
            &b""[..],
            b"null",
            b"[]",
            b"{",
            b"\xff\xfe",
            b"{\"schema\":1}",
        ] {
            assert!(parse_launch_record(bytes).is_err(), "{bytes:?}");
        }
    }

    /// Each value the record carries is held to its field's shape.
    #[test]
    fn a_value_outside_its_shape_is_invalid() {
        let long = "a".repeat(65);
        let cases: Vec<(&str, Vec<&str>, Value)> = vec![
            ("instance_id", vec!["instance_id"], json!("")),
            ("instance_id", vec!["instance_id"], json!("../x")),
            ("instance_id", vec!["instance_id"], json!("A1")),
            ("instance_id", vec!["instance_id"], json!("a.b")),
            ("instance_id", vec!["instance_id"], json!(long)),
            ("agent_type", vec!["agent_type"], json!("Claude")),
            ("agent_type", vec!["agent_type"], json!("")),
            ("agent_type", vec!["agent_type"], json!("a b")),
            ("project", vec!["project"], json!("/home/me/app")),
            ("project", vec!["project"], json!("..")),
            ("project", vec!["project"], json!("a\nb")),
            ("project", vec!["project"], json!("")),
            (
                "launcher.path",
                vec!["launcher", "path"],
                json!("innerwarden"),
            ),
            (
                "launcher.path",
                vec!["launcher", "path"],
                json!("/usr/../tmp/x"),
            ),
            (
                "launcher.path",
                vec!["launcher", "path"],
                json!("/usr/bin/a\u{0}b"),
            ),
            ("launcher.version", vec!["launcher", "version"], json!("")),
            (
                "launcher.version",
                vec!["launcher", "version"],
                json!("1.6.0 rc"),
            ),
            ("jail.pid", vec!["jail", "pid"], json!(0)),
            ("jail.start_ticks", vec!["jail", "start_ticks"], json!(0)),
            ("jail.pid_ns", vec!["jail", "pid_ns"], json!(0)),
            ("jail.mnt_ns", vec!["jail", "mnt_ns"], json!(0)),
            (
                "scope.user.unit",
                vec!["scope", "user", "unit"],
                json!("a/b.scope"),
            ),
            ("scope.user.unit", vec!["scope", "user", "unit"], json!("")),
            (
                "scope.user.cgroup_path",
                vec!["scope", "user", "cgroup_path"],
                json!("user.slice/x"),
            ),
            (
                "scope.user.cgroup_path",
                vec!["scope", "user", "cgroup_path"],
                json!("/a/../b"),
            ),
            (
                "scope.system.unit",
                vec!["scope", "system", "unit"],
                json!(""),
            ),
            (
                "scope.system.cgroup_path",
                vec!["scope", "system", "cgroup_path"],
                json!("system.slice/innerwarden-contain-7f3a9c1e42b84d0e9a6c5f1b2d3e4a59.scope"),
            ),
        ];
        for (field, path, bad) in cases {
            let mut value = golden_json();
            let mut at = &mut value;
            for step in &path[..path.len() - 1] {
                at = &mut at[*step];
            }
            at[path[path.len() - 1]] = bad.clone();
            assert_eq!(
                parse_value(&value),
                Err(RecordError::Invalid(match field {
                    "jail.pid_ns" => "jail.pid_ns is missing for a PID namespace backend",
                    "jail.mnt_ns" => "jail.mnt_ns is missing for a namespace backend",
                    other => other,
                })),
                "{field} = {bad}"
            );
        }
    }

    /// Either scope alone is a valid record, and writes only itself.
    #[test]
    fn either_scope_alone_is_a_valid_record() {
        for (keep, drop) in [("user", "system"), ("system", "user")] {
            let mut value = golden_json();
            value["scope"].as_object_mut().unwrap().remove(drop);
            let record = parse_value(&value).unwrap();
            let scopes = record.scope.as_ref().unwrap();
            assert_eq!(scopes.user.is_some(), keep == "user");
            assert_eq!(scopes.system.is_some(), keep == "system");
            let written = serde_json::to_value(&record).unwrap();
            assert_eq!(written["scope"], value["scope"], "{keep}");
        }
    }

    /// `"scope": {}` names no scope; a reader could take it for one.
    #[test]
    fn a_scope_with_neither_user_nor_system_is_refused() {
        let mut value = golden_json();
        value["scope"] = json!({});
        assert_eq!(
            parse_value(&value),
            Err(RecordError::Invalid("scope has neither user nor system"))
        );
    }

    /// A record cannot borrow another instance's scope, another user's, or a
    /// cgroup the user made and named like a system one.
    #[test]
    fn a_scope_belongs_to_its_own_instance_and_user() {
        let other = "innerwarden-contain-0000aaaa-42.scope";
        let user = |cgroup: &str| -> Value {
            json!({ "unit": "innerwarden-contain-7f3a9c1e42b84d0e9a6c5f1b2d3e4a59.scope", "cgroup_path": cgroup })
        };
        let cases: Vec<(&str, &str, Value)> = vec![
            (
                "user",
                "scope.user.unit",
                json!({ "unit": other, "cgroup_path": format!("/user.slice/user-1000.slice/user@1000.service/app.slice/{other}") }),
            ),
            (
                "user",
                "scope.user.cgroup_path",
                user("/user.slice/user-1001.slice/user@1001.service/app.slice/innerwarden-contain-7f3a9c1e42b84d0e9a6c5f1b2d3e4a59.scope"),
            ),
            (
                "user",
                "scope.user.cgroup_path",
                user(&format!(
                    "/user.slice/user-1000.slice/user@1000.service/app.slice/{other}"
                )),
            ),
            (
                "user",
                "scope.user.cgroup_path",
                user("/system.slice/innerwarden-contain-7f3a9c1e42b84d0e9a6c5f1b2d3e4a59.scope"),
            ),
            (
                "user",
                "scope.user.cgroup_path",
                user("/user.slice/user-1000.slice/session-3.scope/innerwarden-contain-7f3a9c1e42b84d0e9a6c5f1b2d3e4a59.scope"),
            ),
            (
                "system",
                "scope.system.unit",
                json!({ "unit": other, "cgroup_path": format!("/system.slice/{other}") }),
            ),
            (
                "system",
                "scope.system.cgroup_path",
                user("/user.slice/user-1000.slice/user@1000.service/app.slice/system.slice/innerwarden-contain-7f3a9c1e42b84d0e9a6c5f1b2d3e4a59.scope"),
            ),
            (
                "system",
                "scope.system.cgroup_path",
                user("/system.slice/nested.slice/innerwarden-contain-7f3a9c1e42b84d0e9a6c5f1b2d3e4a59.scope"),
            ),
        ];
        for (which, field, bad) in cases {
            let mut value = golden_json();
            value["scope"][which] = bad.clone();
            assert_eq!(
                parse_value(&value),
                Err(RecordError::Invalid(field)),
                "{which} = {bad}"
            );
        }
        // The shapes a real manager produces are accepted: with and without
        // an `app.slice` between the manager and the scope.
        let unit = "innerwarden-contain-7f3a9c1e42b84d0e9a6c5f1b2d3e4a59.scope";
        assert!(is_user_scope_cgroup(
            &format!("/user.slice/user-1000.slice/user@1000.service/{unit}"),
            unit,
            1000
        ));
        assert!(is_user_scope_cgroup(
            &format!("/user.slice/user-1000.slice/user@1000.service/app.slice/{unit}"),
            unit,
            1000
        ));
    }

    #[test]
    fn the_scope_names_and_the_request_are_the_ones_launcher_and_host_share() {
        assert_eq!(SCOPE_UNIT_PREFIX, "innerwarden-contain-");
        assert_eq!(
            scope_unit_name("7f3a9c1e42b84d0e9a6c5f1b2d3e4a59").as_deref(),
            Some("innerwarden-contain-7f3a9c1e42b84d0e9a6c5f1b2d3e4a59.scope")
        );
        for bad in ["", "../x", "A", "a.b", "a/b"] {
            assert_eq!(scope_unit_name(bad), None, "{bad:?}");
            assert_eq!(system_scope_request(bad), None, "{bad:?}");
        }
        assert_eq!(
            system_scope_cgroup("innerwarden-contain-7f3a9c1e42b84d0e9a6c5f1b2d3e4a59.scope"),
            "/system.slice/innerwarden-contain-7f3a9c1e42b84d0e9a6c5f1b2d3e4a59.scope"
        );
        assert_eq!(SYSTEM_SCOPE_ROUTE, "/api/agent/contain-scope");
        // The request names the instance and nothing else: no pid to move.
        assert_eq!(
            system_scope_request("7f3a9c1e42b84d0e9a6c5f1b2d3e4a59").unwrap(),
            json!({ "instance": "7f3a9c1e42b84d0e9a6c5f1b2d3e4a59" })
        );
    }

    fn ended_run(commands: u32, last_ms: Option<u64>) -> ContainedRun<'static> {
        ContainedRun {
            instance_id: "0123456789abcdef0123456789abcdef",
            started_ms: 1_000,
            ended_ms: 9_000,
            graph: JailGraphState::Read,
            commands,
            last_ms,
            host_allowances: 0,
            host_decisions: &[],
        }
    }

    /// The report of an ended run says `declared` whatever it counts, and
    /// carries counts and times, never a command.
    #[test]
    fn a_contained_run_report_is_declared_whatever_it_counts() {
        assert_eq!(CONTAINED_RUN_ROUTE, "/api/agent/contain-run");
        assert_eq!(
            contained_run_report(&ended_run(3, Some(8_000))).unwrap(),
            json!({
                "instance": "0123456789abcdef0123456789abcdef",
                "source": "project_graph",
                "trust": "declared",
                "graph": "read",
                "commands": 3,
                "last_ms": 8_000,
                "started_ms": 1_000,
                "ended_ms": 9_000,
            })
        );
        for run in [
            ended_run(0, None),
            ended_run(u32::MAX, Some(9_000)),
            ended_run(1, Some(1_000)),
            ContainedRun {
                graph: JailGraphState::Absent,
                ..ended_run(0, None)
            },
            ContainedRun {
                graph: JailGraphState::Unreadable,
                ..ended_run(0, None)
            },
        ] {
            let body = contained_run_report(&run).expect("a consistent run");
            assert_eq!(body["trust"], "declared", "{body}");
            assert_eq!(body["source"], "project_graph", "{body}");
            assert_eq!(body["graph"], run.graph.as_str(), "{body}");
            let keys: Vec<&str> = body
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(
                keys,
                [
                    "commands",
                    "ended_ms",
                    "graph",
                    "instance",
                    "last_ms",
                    "source",
                    "started_ms",
                    "trust"
                ]
            );
        }
    }

    /// A run that does not describe itself consistently is not reported:
    /// each case is a consistent run with exactly one thing wrong.
    ///
    /// FAILS ON REVERT: drop any clause of the check and its case is sent.
    #[test]
    fn an_inconsistent_run_makes_no_report() {
        let cases: [(&str, ContainedRun<'static>); 8] = [
            (
                "the id is a path",
                ContainedRun {
                    instance_id: "../x",
                    ..ended_run(0, None)
                },
            ),
            (
                "the window ends before it starts",
                ContainedRun {
                    started_ms: 9_001,
                    ..ended_run(0, None)
                },
            ),
            (
                "the newest command is after the end",
                ended_run(1, Some(9_001)),
            ),
            (
                "the newest command is before the start",
                ended_run(1, Some(999)),
            ),
            ("commands without a newest one", ended_run(2, None)),
            ("a newest one without commands", ended_run(0, Some(5_000))),
            (
                "a count from a graph that was refused",
                ContainedRun {
                    graph: JailGraphState::Unreadable,
                    ..ended_run(1, Some(5_000))
                },
            ),
            (
                "a count from a graph that was not there",
                ContainedRun {
                    graph: JailGraphState::Absent,
                    ..ended_run(1, Some(5_000))
                },
            ),
        ];
        for (wrong, run) in cases {
            assert_eq!(contained_run_report(&run), None, "{wrong}");
        }
    }

    const DECISION: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
    const SHA: &str = "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b";

    fn claim(decision_id: &str) -> HostDecisionClaim {
        HostDecisionClaim {
            decision_id: decision_id.into(),
            command_sha256: SHA.into(),
        }
    }

    /// A run with no host allowance reports the very bytes it reported
    /// before allowances were counted.
    ///
    /// FAILS ON REVERT: write the two keys unconditionally and the body
    /// grows `host_allowances: 0` and `host_decisions: []`.
    #[test]
    fn a_report_without_host_allowances_is_the_body_of_today() {
        let body = contained_run_report(&ended_run(3, Some(8_000))).unwrap();
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"commands":3,"ended_ms":9000,"graph":"read","instance":"0123456789abcdef0123456789abcdef","last_ms":8000,"source":"project_graph","started_ms":1000,"trust":"declared"}"#
        );
    }

    /// Host allowances are a part of the commands counted, and each names
    /// the decision and the command it claims.
    #[test]
    fn a_report_with_host_allowances_names_each_decision_once() {
        let claims = [claim(DECISION)];
        let body = contained_run_report(&ContainedRun {
            host_allowances: 2,
            host_decisions: &claims,
            ..ended_run(3, Some(8_000))
        })
        .unwrap();
        assert_eq!(body["host_allowances"], 2);
        assert_eq!(
            body["host_decisions"],
            json!([{"decision_id": DECISION, "command_sha256": SHA}])
        );
        assert_eq!(body["trust"], "declared", "the jail's own word still");
    }

    /// FAILS ON REVERT: drop any of the host clauses of the check and its
    /// case is sent.
    #[test]
    fn host_allowances_that_do_not_add_up_make_no_report() {
        let one = [claim(DECISION)];
        let twice = [claim(DECISION), claim(DECISION)];
        let bad = [claim("not-a-decision")];
        let mut bad_sha = [claim(DECISION)];
        bad_sha[0].command_sha256 = "ABC".into();
        let cases: [(&str, ContainedRun<'_>); 6] = [
            (
                "more allowances than commands",
                ContainedRun {
                    host_allowances: 4,
                    host_decisions: &one,
                    ..ended_run(3, Some(8_000))
                },
            ),
            (
                "allowances without decisions",
                ContainedRun {
                    host_allowances: 1,
                    ..ended_run(3, Some(8_000))
                },
            ),
            (
                "decisions without allowances",
                ContainedRun {
                    host_decisions: &one,
                    ..ended_run(3, Some(8_000))
                },
            ),
            (
                "the same pair twice",
                ContainedRun {
                    host_allowances: 2,
                    host_decisions: &twice,
                    ..ended_run(3, Some(8_000))
                },
            ),
            (
                "a decision id that is not one",
                ContainedRun {
                    host_allowances: 1,
                    host_decisions: &bad,
                    ..ended_run(3, Some(8_000))
                },
            ),
            (
                "a hash that is not one",
                ContainedRun {
                    host_allowances: 1,
                    host_decisions: &bad_sha,
                    ..ended_run(3, Some(8_000))
                },
            ),
        ];
        for (wrong, run) in cases {
            assert_eq!(contained_run_report(&run), None, "{wrong}");
        }
    }

    // -- asking the host ------------------------------------------------------

    const OWN: &str = "7f3a9c1e42b84d0e9a6c5f1b2d3e4a59";

    #[test]
    fn the_route_and_the_key_file_are_pinned() {
        assert_eq!(INSTANCE_DECIDE_ROUTE, "/api/agent/instance-decide");
        assert_eq!(AGENT_TLS_SPKI_PATH, "/etc/innerwarden/agent-tls.spki");
        assert_eq!(JAIL_SPKI_PIN_PATH, "/run/innerwarden/agent-tls.spki");
        assert_eq!(
            Path::new(JAIL_SPKI_PIN_PATH).parent(),
            Path::new(JAIL_RECORD_PATH).parent(),
            "the key lands beside the record"
        );
        assert_eq!(HOST_TRUST_SOURCE, "host");
        assert_eq!(HOST_ANSWER_INVALID, "host_answer_invalid");
        assert!(is_withheld_word(HOST_ANSWER_INVALID));
    }

    /// An `atr:` label is a signal the request carries, not a reason to
    /// refuse building it.
    ///
    /// FAILS ON REVERT: accept only the profile vocabulary in
    /// `is_hook_signal` and the label is dropped.
    #[test]
    fn a_review_with_an_atr_signal_is_sent_not_refused() {
        let request = instance_decide_request(
            OWN,
            Some("claude-code"),
            Some("s-1"),
            "curl http://203.0.113.9/x",
            &["atr:tool-poisoning", "bare_ip_fetch"],
            false,
        )
        .expect("a request");
        assert_eq!(
            request.hook_signals,
            ["atr:tool-poisoning", "bare_ip_fetch"]
        );
        assert!(request.is_valid());
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            json!({
                "v": 1,
                "instance_id": OWN,
                "claimed_agent_type": "claude-code",
                "session_id": "s-1",
                "command": "curl http://203.0.113.9/x",
                "hook_signals": ["atr:tool-poisoning", "bare_ip_fetch"],
                "tainted": false,
                "hook_verdict": "review",
                "hook_layer": "general",
            })
        );
    }

    /// A session id or a type out of shape is sent as `null`, never cut or
    /// repaired; an id that is not one, or no command, sends nothing.
    #[test]
    fn a_session_id_out_of_shape_is_sent_as_null() {
        for session in ["", "a b", "x".repeat(129).as_str(), "s…", "[REDACTED]"] {
            let request =
                instance_decide_request(OWN, Some("claude-code"), Some(session), "ls", &[], true)
                    .unwrap();
            assert_eq!(request.session_id, None, "{session:?}");
            assert!(request.tainted);
            assert!(request.is_valid());
        }
        let long = "A-z_9".repeat(25);
        let request = instance_decide_request(OWN, None, Some(&long), "ls", &[], false).unwrap();
        assert_eq!(request.session_id.as_deref(), Some(long.as_str()));
        let odd =
            instance_decide_request(OWN, Some("Claude Code"), None, "ls", &[], false).unwrap();
        assert_eq!(odd.claimed_agent_type, None);
        assert_eq!(
            instance_decide_request("../x", None, None, "ls", &[], false),
            None
        );
        assert_eq!(
            instance_decide_request(OWN, None, None, "", &[], false),
            None
        );
    }

    /// The signals go sorted and once each; a name the contract does not
    /// carry is left out; never more than the cap.
    #[test]
    fn the_signals_are_sorted_and_sent_once() {
        let request = instance_decide_request(
            OWN,
            None,
            None,
            "x",
            &[
                "fetch_exec_no_tls",
                "bare_ip_fetch",
                "fetch_exec_no_tls",
                "atr:BAD",
                "made_up",
                "download_and_execute",
            ],
            false,
        )
        .unwrap();
        assert_eq!(
            request.hook_signals,
            ["bare_ip_fetch", "download_and_execute", "fetch_exec_no_tls"]
        );
        let many: Vec<String> = (0..100).map(|i| format!("atr:c{i:03}")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        let capped = instance_decide_request(OWN, None, None, "x", &many, false).unwrap();
        assert_eq!(capped.hook_signals.len(), MAX_HOOK_SIGNALS);
        assert!(capped.is_valid());
    }

    #[test]
    fn a_hook_signal_is_a_profile_name_a_factor_or_an_atr_label() {
        for good in [
            "bare_ip_fetch",
            "fetch_exec_decoder",
            "atr:tool-poisoning",
            "atr:a_1",
        ] {
            assert!(is_hook_signal(good), "{good}");
        }
        for bad in [
            "",
            "atr:",
            "atr:Tool",
            "atr:a b",
            "nope",
            &format!("atr:{}", "a".repeat(65)),
        ] {
            assert!(!is_hook_signal(bad), "{bad}");
        }
    }

    /// The host reads a request with every field present and nothing more:
    /// a `trust` the hook added is refused, and so is a missing nullable.
    #[test]
    fn a_request_is_read_with_its_fields_and_no_other() {
        let good = json!({
            "v": 1, "instance_id": OWN, "claimed_agent_type": null, "session_id": null,
            "command": "ls", "hook_signals": [], "tainted": false,
            "hook_verdict": "review", "hook_layer": "general",
        });
        let read: InstanceDecideRequest = serde_json::from_value(good.clone()).unwrap();
        assert!(read.is_valid());
        let mut extra = good.clone();
        extra["trust"] = json!("confined");
        assert!(serde_json::from_value::<InstanceDecideRequest>(extra).is_err());
        let mut missing = good.clone();
        missing.as_object_mut().unwrap().remove("session_id");
        assert!(serde_json::from_value::<InstanceDecideRequest>(missing).is_err());
        for (field, value) in [
            ("v", json!(2)),
            ("hook_verdict", json!("allow")),
            ("hook_layer", json!("agent_type")),
            ("command", json!("")),
            (
                "hook_signals",
                json!(["download_and_execute", "bare_ip_fetch"]),
            ),
            ("hook_signals", json!(["made_up"])),
            ("instance_id", json!("../x")),
            ("claimed_agent_type", json!("Claude Code")),
            ("session_id", json!("a b")),
            ("hook_signals", json!(["bare_ip_fetch", "bare_ip_fetch"])),
        ] {
            let mut wrong = good.clone();
            wrong[field] = value;
            let accepted = serde_json::from_value::<InstanceDecideRequest>(wrong.clone())
                .is_ok_and(|request| request.is_valid());
            assert!(!accepted, "{wrong}");
        }
    }

    fn answer() -> Value {
        json!({
            "v": 1, "instance_id": OWN, "agent_type": "claude-code", "trust": "confined",
            "trust_source": "host", "verdict": "allow", "deciding_layer": "agent_type",
            "profile": "claude-code", "decision_id": DECISION, "withheld": null,
            "signals_mismatch": false, "conflict": false, "incident_id": null,
        })
    }

    fn read(value: &Value) -> HostAnswer {
        read_host_answer(&serde_json::to_vec(value).unwrap(), OWN)
    }

    #[test]
    fn the_contracts_answer_is_read_and_relaxes() {
        let HostAnswer::Answer(read) = read(&answer()) else {
            panic!("the contract's answer")
        };
        assert!(read.relaxes());
        assert_eq!(read.verdict, Verdict::Allow);
        assert_eq!(read.deciding_layer, RuleLayer::AgentType);
        assert_eq!(read.decision_id, DECISION);
    }

    /// FAILS ON REVERT: accept an answer without comparing `instance_id` and
    /// another instance's allow is read as this one's.
    #[test]
    fn an_answer_for_another_instance_is_withheld() {
        let mut other = answer();
        other["instance_id"] = json!("fedcba9876543210fedcba9876543210");
        assert_eq!(read(&other), HostAnswer::Withheld);
        assert_eq!(
            read_host_answer(&serde_json::to_vec(&answer()).unwrap(), "../x"),
            HostAnswer::Withheld
        );
    }

    /// FAILS ON REVERT: drop `deny_unknown_fields` from
    /// `InstanceDecideAnswer` and the answer with a field more is read.
    #[test]
    fn an_answer_with_an_extra_field_is_withheld() {
        let mut extra = answer();
        extra["blocks"] = json!(false);
        assert_eq!(read(&extra), HostAnswer::Withheld);
    }

    /// Every field must be there and hold its shape: one wrong at a time.
    #[test]
    fn an_answer_out_of_shape_is_withheld() {
        let mut cases: Vec<(&str, Value)> = Vec::new();
        for field in [
            "v",
            "instance_id",
            "agent_type",
            "trust",
            "trust_source",
            "verdict",
            "deciding_layer",
            "profile",
            "decision_id",
            "withheld",
            "signals_mismatch",
            "conflict",
            "incident_id",
        ] {
            let mut missing = answer();
            missing.as_object_mut().unwrap().remove(field);
            cases.push((field, missing));
        }
        for (field, value) in [
            ("v", json!(2)),
            ("trust", json!("host_verified")),
            ("trust_source", json!("jail")),
            ("verdict", json!("maybe")),
            ("deciding_layer", json!("person")),
            ("decision_id", json!("0F1E2D3C4B5A69788796A5B4C3D2E1F0")),
            ("decision_id", json!("short")),
            ("withheld", json!("Not Confined")),
            ("withheld", json!("")),
            ("withheld", json!("a".repeat(49))),
            ("agent_type", json!("Claude Code")),
            ("profile", json!("../x")),
            ("incident_id", json!("")),
        ] {
            let mut wrong = answer();
            wrong[field] = value;
            cases.push((field, wrong));
        }
        for (field, case) in cases {
            assert_eq!(read(&case), HostAnswer::Withheld, "{field}: {case}");
        }
        assert_eq!(read_host_answer(b"not json", OWN), HostAnswer::Withheld);
        let mut padded = serde_json::to_vec(&answer()).unwrap();
        padded.resize(MAX_INSTANCE_ANSWER_BYTES + 1, b' ');
        assert_eq!(read_host_answer(&padded, OWN), HostAnswer::Withheld);
    }

    /// Only `confined` with nothing withheld relaxes; a word, whatever it
    /// is, or another trust, does not.
    #[test]
    fn only_confined_with_nothing_withheld_relaxes() {
        for (trust, withheld, relaxes) in [
            ("confined", Value::Null, true),
            ("confined", json!("no_system_scope"), false),
            ("confined", json!("some_word_this_build_never_heard"), false),
            ("observed", Value::Null, false),
            ("declared", Value::Null, false),
        ] {
            let mut case = answer();
            case["trust"] = json!(trust);
            case["withheld"] = withheld.clone();
            let HostAnswer::Answer(read) = read(&case) else {
                panic!("{case}")
            };
            assert_eq!(read.relaxes(), relaxes, "{trust} {withheld}");
        }
    }

    #[test]
    fn the_key_file_holds_one_hex_digest() {
        let digest: [u8; 32] = core::array::from_fn(|i| (i * 7) as u8);
        let line = spki_pin_line(&digest);
        assert_eq!(line.len(), MAX_SPKI_PIN_BYTES);
        assert_eq!(parse_spki_pin(line.as_bytes()), Some(digest));
        assert_eq!(parse_spki_pin(line.trim_end().as_bytes()), Some(digest));
        for bad in [
            line.to_uppercase(),
            format!("{line}\n"),
            format!(" {line}"),
            line[..63].to_string(),
            String::new(),
        ] {
            assert_eq!(parse_spki_pin(bad.as_bytes()), None, "{bad:?}");
        }
    }

    /// A backend with no PID namespace cannot claim one.
    #[test]
    fn a_sandbox_exec_record_carries_no_namespace() {
        let mut value = golden_json();
        value["jail"]["backend"] = json!("sandbox-exec");
        assert!(matches!(parse_value(&value), Err(RecordError::Invalid(_))));
        value["jail"]["pid_ns"] = json!(0);
        assert!(matches!(parse_value(&value), Err(RecordError::Invalid(_))));
        value["jail"]["mnt_ns"] = json!(0);
        assert!(parse_value(&value).is_ok());
    }

    #[test]
    fn a_record_file_name_comes_only_from_a_well_formed_id() {
        assert_eq!(
            instance_record_file("7f3a9c1e42b84d0e9a6c5f1b2d3e4a59").as_deref(),
            Some("7f3a9c1e42b84d0e9a6c5f1b2d3e4a59.json")
        );
        for bad in [
            "",
            "../etc/passwd",
            "a/b",
            "A",
            "a.json",
            "a\u{0}",
            &"a".repeat(65),
        ] {
            assert_eq!(instance_record_file(bad), None, "{bad:?}");
        }
    }

    /// An instance id is the launcher's shape and only that: 32 lowercase
    /// hex characters. A dash, a letter past `f`, upper case, or any other
    /// length is not an id, so it never becomes a file, a unit or a key the
    /// dashboard serves.
    ///
    /// FAILS ON REVERT: accept `[a-z0-9-]{1,64}` again and the short, dashed
    /// and non-hex ids below pass.
    #[test]
    fn an_instance_id_is_exactly_32_lowercase_hex() {
        assert_eq!(INSTANCE_ID_LEN, 32);
        assert!(is_instance_id("7f3a9c1e42b84d0e9a6c5f1b2d3e4a59"));
        assert!(is_instance_id(&"0".repeat(32)));
        for bad in [
            "7f3a9c1e-42",
            "7f3a9c1e42b84d0e9a6c5f1b2d3e4a5",
            "7f3a9c1e42b84d0e9a6c5f1b2d3e4a590",
            "7f3a9c1e42b84d0e9a6c5f1b2d3e4a5g",
            "7F3A9C1E42B84D0E9A6C5F1B2D3E4A59",
            "7f3a9c1e-2b84d0e9a6c5f1b2d3e4a59",
            &"z".repeat(32),
            &"a".repeat(64),
        ] {
            assert!(!is_instance_id(bad), "{bad:?}");
            assert_eq!(scope_unit_name(bad), None, "{bad:?}");
            assert_eq!(system_scope_request(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_names_are_the_ones_the_launcher_and_hook_share() {
        assert_eq!(IDENTITY_FLAG, "--identity");
        assert_eq!(JAIL_RECORD_PATH, "/run/innerwarden/instance.json");
        assert_eq!(LAUNCHER_RECORD_DIR, "innerwarden/instances");
        assert_eq!(HOOK_AGENT_ENV, "IW_HOOK_AGENT");
    }

    // -- trust inside the jail ---------------------------------------------

    const OWN_NS: u64 = 4026532871;
    const OWN_MNT: u64 = 4026532869;

    fn facts<'a>(record: &'a LaunchRecord, read_only: bool, own: Option<u64>) -> InJailFacts<'a> {
        InJailFacts {
            record: RecordRead::Present { record, read_only },
            own_pid_ns: own,
            own_mnt_ns: Some(OWN_MNT),
        }
    }

    /// Row 10: everything the reading checks holds, and it is still
    /// `observed`.
    ///
    /// FAILS ON REVERT: return `confined` from row 10 and every case here
    /// sees `confined`.
    #[test]
    fn row_10_same_namespace_read_only_record_root_owned_launcher_and_a_scope_is_observed() {
        let record = golden();
        assert_eq!(
            judge_trust_in_jail(facts(&record, true, Some(OWN_NS))),
            (Trust::Observed, Reason::ConfinedByNamespace)
        );
        // Either scope on its own is a cgroup the instance was put in.
        for drop_user in [false, true] {
            let mut record = golden();
            let scopes = record.scope.as_mut().unwrap();
            if drop_user {
                scopes.user = None;
            } else {
                scopes.system = None;
            }
            assert_eq!(
                judge_trust_in_jail(facts(&record, true, Some(OWN_NS))),
                (Trust::Observed, Reason::ConfinedByNamespace)
            );
        }
    }

    /// The record an agent writes for itself, in a user and mount namespace
    /// it made: its own namespace inodes, a root-owned launcher, a scope named
    /// for an id it chose, the type it wants, on a mount it remounted
    /// read-only. Every fact matches, so the reading cannot tell it from the
    /// launcher's, and it earns no level that unlocks a relaxation: under a
    /// profile and an exception that allow the call, the general review
    /// stands.
    ///
    /// FAILS ON REVERT: return `confined` from row 10 and the exception lets
    /// the forged instance through.
    #[test]
    fn a_record_the_agent_made_for_itself_unlocks_no_relaxation() {
        const FORGED_PID: u64 = 4026533001;
        const FORGED_MNT: u64 = 4026533002;
        let forged = parse_launch_record(
            br#"{"schema":1,"instance_id":"000000000000000000000000000000a1","agent_type":"permissive","launcher":{"path":"/usr/local/bin/innerwarden","version":"1","root_owned":true},"uid":1000,"project":"p","mode":"enforce","started_at":"2026-10-16T09:30:00Z","jail":{"backend":"bwrap","pid":1,"start_ticks":1,"pid_ns":4026533001,"mnt_ns":4026533002},"scope":{"user":{"unit":"innerwarden-contain-000000000000000000000000000000a1.scope","cgroup_path":"/user.slice/user-1000.slice/user@1000.service/app.slice/innerwarden-contain-000000000000000000000000000000a1.scope"}}}"#,
        )
        .expect("a well-formed record");
        let judged = judge_trust_in_jail(InJailFacts {
            record: RecordRead::Present {
                record: &forged,
                read_only: true,
            },
            own_pid_ns: Some(FORGED_PID),
            own_mnt_ns: Some(FORGED_MNT),
        });
        let (trust, _) = judge_agent_claim(judged, &forged.agent_type, Some("permissive"));
        assert_eq!(trust, Trust::Observed);
        let allowed_by_profile = Layers {
            hard_refused: false,
            general: Verdict::Review,
            agent_type: Some(LayerRule::Allow),
            instance: Some(LayerRule::Allow),
        };
        assert_eq!(
            decide(allowed_by_profile, trust),
            Decision {
                verdict: Verdict::Review,
                deciding_layer: RuleLayer::General,
            }
        );
    }

    /// Row 9: a launch with no dedicated scope (no user service manager) is
    /// `observed` at most, however well everything else matches. The launcher
    /// says so on screen; this is what keeps that sentence true.
    #[test]
    fn row_9_a_jail_in_no_scope_is_observed_at_most() {
        let mut record = golden();
        record.scope = None;
        assert_eq!(
            judge_trust_in_jail(facts(&record, true, Some(OWN_NS))),
            (Trust::Observed, Reason::NoScope)
        );
        // An empty scope set is refused by the reader as unreadable.
        record.scope = Some(Scopes::default());
        assert_eq!(
            judge_trust_in_jail(facts(&record, true, Some(OWN_NS))),
            (Trust::Declared, Reason::RecordUnreadable)
        );
    }

    #[test]
    fn row_1_no_record_is_declared() {
        let judged = judge_trust_in_jail(InJailFacts {
            record: RecordRead::Absent,
            own_pid_ns: Some(OWN_NS),
            own_mnt_ns: Some(OWN_MNT),
        });
        assert_eq!(judged, (Trust::Declared, Reason::NoRecord));
    }

    #[test]
    fn row_2_an_unusable_record_is_declared() {
        let judged = judge_trust_in_jail(InJailFacts {
            record: RecordRead::Unreadable,
            own_pid_ns: Some(OWN_NS),
            own_mnt_ns: Some(OWN_MNT),
        });
        assert_eq!(judged, (Trust::Declared, Reason::RecordUnreadable));
    }

    /// A record built by hand that would not pass the parser is not trusted
    /// either: the judge does not rely on its caller having validated.
    #[test]
    fn row_2_a_present_record_that_fails_validation_is_declared() {
        let mut record = golden();
        record.jail.start_ticks = 0;
        assert_eq!(
            judge_trust_in_jail(facts(&record, true, Some(OWN_NS))),
            (Trust::Declared, Reason::RecordUnreadable)
        );
    }

    #[test]
    fn row_3_a_record_the_agent_could_write_is_declared() {
        let record = golden();
        assert_eq!(
            judge_trust_in_jail(facts(&record, false, Some(OWN_NS))),
            (Trust::Declared, Reason::RecordWritable)
        );
    }

    #[test]
    fn row_4_a_backend_with_no_namespace_is_declared() {
        let mut record = golden();
        record.jail.backend = JailBackend::SandboxExec;
        record.jail.pid_ns = 0;
        record.jail.mnt_ns = 0;
        assert_eq!(
            judge_trust_in_jail(facts(&record, true, Some(OWN_NS))),
            (Trust::Declared, Reason::NoNamespaceOnBackend)
        );
        // Even if the hook somehow matched nothing-to-nothing.
        assert_eq!(
            judge_trust_in_jail(facts(&record, true, Some(0))),
            (Trust::Declared, Reason::NoNamespaceOnBackend)
        );
    }

    /// The host's own namespace matches every process on the machine.
    #[test]
    fn row_5_a_record_naming_the_host_namespace_is_declared() {
        let mut record = golden();
        record.jail.pid_ns = INITIAL_PID_NS_INODE;
        assert_eq!(
            judge_trust_in_jail(facts(&record, true, Some(INITIAL_PID_NS_INODE))),
            (Trust::Declared, Reason::HostNamespaceRecorded)
        );
    }

    #[test]
    fn row_6_an_unreadable_own_namespace_is_declared() {
        let record = golden();
        assert_eq!(
            judge_trust_in_jail(facts(&record, true, None)),
            (Trust::Declared, Reason::OwnNamespaceUnreadable)
        );
    }

    #[test]
    fn row_7_a_record_for_another_namespace_is_declared() {
        let record = golden();
        for other in [OWN_NS + 1, OWN_NS - 1, 1, INITIAL_PID_NS_INODE] {
            assert_eq!(
                judge_trust_in_jail(facts(&record, true, Some(other))),
                (Trust::Declared, Reason::NamespaceMismatch),
                "{other}"
            );
        }
    }

    /// Row 7 for a nested PID namespace: a process that made its own (for
    /// example `unshare -Upf`) reads a namespace that is not the recorded one.
    #[test]
    fn row_7_a_nested_pid_namespace_is_not_the_recorded_one() {
        let record = golden();
        let nested = OWN_NS + 7;
        let mut facts = facts(&record, true, Some(nested));
        facts.own_mnt_ns = Some(OWN_MNT);
        assert_eq!(
            judge_trust_in_jail(facts),
            (Trust::Declared, Reason::NamespaceMismatch)
        );
    }

    /// Row 7a: the namespace that holds the record's mount cannot be read.
    ///
    /// FAILS ON REVERT: drop the mount namespace rows from
    /// `judge_trust_in_jail` and this is `confined`.
    #[test]
    fn row_7a_an_unreadable_own_mount_namespace_is_declared() {
        let record = golden();
        let mut facts = facts(&record, true, Some(OWN_NS));
        facts.own_mnt_ns = None;
        assert_eq!(
            judge_trust_in_jail(facts),
            (Trust::Declared, Reason::OwnMountNamespaceUnreadable)
        );
    }

    /// Row 7b: same PID namespace, another mount namespace. A process in the
    /// jail that made a mount namespace of its own (`unshare -Urm`, a nested
    /// sandbox) sees a filesystem the launcher did not build, and whatever is
    /// at the record's place there is not the launcher's word.
    ///
    /// FAILS ON REVERT: drop the mount namespace rows from
    /// `judge_trust_in_jail` and every case here is `confined`.
    #[test]
    fn row_7b_another_mount_namespace_in_the_same_pid_namespace_is_declared() {
        let record = golden();
        for other in [OWN_MNT + 1, OWN_MNT - 1, 1, OWN_NS] {
            let mut facts = facts(&record, true, Some(OWN_NS));
            facts.own_mnt_ns = Some(other);
            assert_eq!(
                judge_trust_in_jail(facts),
                (Trust::Declared, Reason::MountNamespaceMismatch),
                "{other}"
            );
        }
    }

    /// A per-user launcher is the ceiling, however well everything else
    /// matches.
    #[test]
    fn row_8_a_launcher_the_user_could_replace_is_observed_at_most() {
        let mut record = golden();
        record.launcher.root_owned = false;
        assert_eq!(
            judge_trust_in_jail(facts(&record, true, Some(OWN_NS))),
            (Trust::Observed, Reason::LauncherNotTrusted)
        );
    }

    /// The order matters: a mismatch is reported as a mismatch even when the
    /// launcher is also untrusted, and never rises to observed.
    #[test]
    fn a_mismatch_beats_an_untrusted_launcher() {
        let mut record = golden();
        record.launcher.root_owned = false;
        assert_eq!(
            judge_trust_in_jail(facts(&record, true, Some(OWN_NS + 1))),
            (Trust::Declared, Reason::NamespaceMismatch)
        );
    }

    /// Of every combination of the inputs, none reaches `confined`, and
    /// exactly one is row 10 (counted once per scope shape that names a
    /// scope).
    ///
    /// FAILS ON REVERT: return `confined` from row 10.
    #[test]
    fn no_reading_reaches_confined_and_row_10_is_exactly_one_combination() {
        let mut row_10 = 0;
        for root_owned in [false, true] {
            for read_only in [false, true] {
                for own in [
                    None,
                    Some(OWN_NS),
                    Some(OWN_NS + 1),
                    Some(INITIAL_PID_NS_INODE),
                ] {
                    for backend_bwrap in [false, true] {
                        for scoped in [false, true] {
                            for own_mnt in [None, Some(OWN_MNT), Some(OWN_MNT + 1)] {
                                let mut record = golden();
                                record.launcher.root_owned = root_owned;
                                if !backend_bwrap {
                                    record.jail.backend = JailBackend::SandboxExec;
                                    record.jail.pid_ns = 0;
                                    record.jail.mnt_ns = 0;
                                }
                                if !scoped {
                                    record.scope = None;
                                }
                                let mut facts = facts(&record, read_only, own);
                                facts.own_mnt_ns = own_mnt;
                                let (judged, reason) = judge_trust_in_jail(facts);
                                assert!(judged <= Trust::Observed, "{judged:?} {reason:?}");
                                if reason == Reason::ConfinedByNamespace {
                                    row_10 += 1;
                                    assert!(
                                        root_owned
                                            && read_only
                                            && backend_bwrap
                                            && scoped
                                            && own == Some(OWN_NS)
                                            && own_mnt == Some(OWN_MNT)
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(row_10, 1);
    }

    #[test]
    fn a_reason_is_spelled_the_same_in_serde_and_as_str() {
        for reason in [
            Reason::ConfinedByNamespace,
            Reason::LauncherNotTrusted,
            Reason::NoScope,
            Reason::NoRecord,
            Reason::RecordUnreadable,
            Reason::RecordWritable,
            Reason::NoNamespaceOnBackend,
            Reason::HostNamespaceRecorded,
            Reason::OwnNamespaceUnreadable,
            Reason::NamespaceMismatch,
            Reason::OwnMountNamespaceUnreadable,
            Reason::MountNamespaceMismatch,
            Reason::AgentMismatch,
            Reason::AgentNotNamed,
        ] {
            assert_eq!(
                serde_json::to_value(reason).unwrap(),
                json!(reason.as_str())
            );
        }
    }

    #[test]
    fn a_hook_wired_for_another_agent_drops_the_level_to_declared() {
        let confined = (Trust::Confined, Reason::ConfinedByNamespace);
        let observed = (Trust::Observed, Reason::NoScope);
        for judged in [confined, observed] {
            assert_eq!(
                judge_agent_claim(judged, "claude-code", Some("cursor")),
                (Trust::Declared, Reason::AgentMismatch)
            );
            assert_eq!(
                judge_agent_claim(judged, "claude-code", Some("claude-code")),
                judged
            );
        }
        // Already declared: the first reason stays.
        let first = (Trust::Declared, Reason::NamespaceMismatch);
        assert_eq!(
            judge_agent_claim(first, "claude-code", Some("cursor")),
            first
        );
    }

    /// A hook that names no agent cannot be held to the record's type, so it
    /// earns nothing above `declared` from the record.
    ///
    /// FAILS ON REVERT: let `judge_agent_claim` leave the level alone when
    /// `hook_agent` is `None`, and the confined and observed cases keep their
    /// level.
    #[test]
    fn a_hook_that_names_no_agent_is_declared() {
        for judged in [
            (Trust::Confined, Reason::ConfinedByNamespace),
            (Trust::Observed, Reason::NoScope),
        ] {
            assert_eq!(
                judge_agent_claim(judged, "claude-code", None),
                (Trust::Declared, Reason::AgentNotNamed)
            );
        }
        let first = (Trust::Declared, Reason::RecordWritable);
        assert_eq!(judge_agent_claim(first, "claude-code", None), first);
    }

    // -- the layers ---------------------------------------------------------

    use LayerRule::{Allow as RAllow, Deny as RDeny};
    use Verdict::{Allow, Deny, Review};

    fn layers(
        hard: bool,
        general: Verdict,
        agent_type: Option<LayerRule>,
        instance: Option<LayerRule>,
    ) -> Layers {
        Layers {
            hard_refused: hard,
            general,
            agent_type,
            instance,
        }
    }

    fn decided(l: Layers, trust: Trust) -> (Verdict, RuleLayer) {
        let d = decide(l, trust);
        (d.verdict, d.deciding_layer)
    }

    const ALL_TRUST: [Trust; 3] = [Trust::Declared, Trust::Observed, Trust::Confined];

    #[test]
    fn a_hard_refusal_wins_at_every_trust_and_over_every_allow() {
        for trust in ALL_TRUST {
            for general in [Allow, Review, Deny] {
                assert_eq!(
                    decided(layers(true, general, Some(RAllow), Some(RAllow)), trust),
                    (Deny, RuleLayer::Hard)
                );
            }
        }
    }

    /// The whole point: a relaxation is for a confined instance only.
    #[test]
    fn a_profile_allow_relaxes_a_review_only_when_confined() {
        let l = layers(false, Review, Some(RAllow), None);
        assert_eq!(decided(l, Trust::Confined), (Allow, RuleLayer::AgentType));
        assert_eq!(decided(l, Trust::Observed), (Review, RuleLayer::General));
        assert_eq!(decided(l, Trust::Declared), (Review, RuleLayer::General));
    }

    /// "An agent declared as the permissive type gets the general policy."
    #[test]
    fn an_instance_allow_relaxes_a_review_only_when_confined() {
        let l = layers(false, Review, None, Some(RAllow));
        assert_eq!(decided(l, Trust::Confined), (Allow, RuleLayer::Instance));
        assert_eq!(decided(l, Trust::Observed), (Review, RuleLayer::General));
        assert_eq!(decided(l, Trust::Declared), (Review, RuleLayer::General));
    }

    #[test]
    fn the_narrowest_allow_is_named() {
        let l = layers(false, Review, Some(RAllow), Some(RAllow));
        assert_eq!(decided(l, Trust::Confined), (Allow, RuleLayer::Instance));
    }

    #[test]
    fn any_deny_wins_at_every_trust() {
        for trust in ALL_TRUST {
            assert_eq!(
                decided(layers(false, Deny, Some(RAllow), Some(RAllow)), trust),
                (Deny, RuleLayer::General)
            );
            assert_eq!(
                decided(layers(false, Allow, Some(RDeny), None), trust),
                (Deny, RuleLayer::AgentType)
            );
            assert_eq!(
                decided(layers(false, Allow, None, Some(RDeny)), trust),
                (Deny, RuleLayer::Instance)
            );
        }
    }

    /// An allow in a narrower layer does not lift a deny in a wider one, even
    /// for a confined instance.
    #[test]
    fn a_narrower_allow_never_lifts_a_wider_deny() {
        assert_eq!(
            decided(
                layers(false, Allow, Some(RDeny), Some(RAllow)),
                Trust::Confined
            ),
            (Deny, RuleLayer::AgentType)
        );
        assert_eq!(
            decided(layers(false, Deny, None, Some(RAllow)), Trust::Confined),
            (Deny, RuleLayer::General)
        );
    }

    #[test]
    fn when_several_layers_deny_the_widest_is_named() {
        let l = layers(false, Deny, Some(RDeny), Some(RDeny));
        assert_eq!(decided(l, Trust::Confined), (Deny, RuleLayer::General));
        let l = layers(false, Allow, Some(RDeny), Some(RDeny));
        assert_eq!(decided(l, Trust::Confined), (Deny, RuleLayer::AgentType));
    }

    #[test]
    fn with_nothing_narrower_the_general_verdict_stands() {
        for trust in ALL_TRUST {
            for general in [Allow, Review] {
                assert_eq!(
                    decided(layers(false, general, None, None), trust),
                    (general, RuleLayer::General)
                );
            }
        }
    }

    /// Exhaustive over every input: a relaxation is never the result unless the
    /// instance is confined and nothing wider refused it.
    #[test]
    fn nothing_but_a_confined_instance_is_ever_relaxed() {
        let verdicts = [Allow, Review, Deny];
        let rules = [None, Some(RAllow), Some(RDeny)];
        for hard in [false, true] {
            for general in verdicts {
                for agent_type in rules {
                    for instance in rules {
                        for trust in ALL_TRUST {
                            let l = layers(hard, general, agent_type, instance);
                            let d = decide(l, trust);
                            let looser = |a: Verdict, b: Verdict| {
                                let rank = |v| match v {
                                    Allow => 0,
                                    Review => 1,
                                    Deny => 2,
                                };
                                rank(a) < rank(b)
                            };
                            if looser(d.verdict, general) {
                                assert_eq!(trust, Trust::Confined, "{l:?}");
                                assert!(!hard, "{l:?}");
                                assert!(
                                    matches!(
                                        d.deciding_layer,
                                        RuleLayer::AgentType | RuleLayer::Instance
                                    ),
                                    "{l:?}"
                                );
                            }
                            if hard {
                                assert_eq!(d.verdict, Deny, "{l:?}");
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn layers_are_ordered_widest_first_and_spelled_stably() {
        assert!(RuleLayer::Hard < RuleLayer::General);
        assert!(RuleLayer::General < RuleLayer::AgentType);
        assert!(RuleLayer::AgentType < RuleLayer::Instance);
        for layer in [
            RuleLayer::Hard,
            RuleLayer::General,
            RuleLayer::AgentType,
            RuleLayer::Instance,
        ] {
            assert_eq!(serde_json::to_value(layer).unwrap(), json!(layer.as_str()));
        }
        for (verdict, word) in [(Allow, "allow"), (Review, "review"), (Deny, "deny")] {
            assert_eq!(serde_json::to_value(verdict).unwrap(), json!(word));
        }
    }

    // -- the hard layer -----------------------------------------------------

    #[test]
    fn every_member_of_the_review_floor_is_hard() {
        assert!(!AGENT_REVIEW_FLOOR.is_empty());
        for signal in AGENT_REVIEW_FLOOR {
            assert!(is_hard_signal(signal), "{signal}");
        }
    }

    #[test]
    fn an_ordinary_signal_is_not_hard() {
        for signal in [
            "destructive_command",
            "bare_ip_fetch",
            "tmp_execution",
            "",
            "x",
        ] {
            assert!(!is_hard_signal(signal), "{signal:?}");
        }
    }

    /// A name in the list that no producer emits any more would be a hard rule
    /// that protects nothing and says nothing. Each one is made to fire by the
    /// engine that produces it.
    #[test]
    fn every_extra_hard_signal_is_one_the_engine_really_emits() {
        let fired = |command: &str| -> Vec<String> {
            crate::mcp::analyze_command(command, None)
                .signals
                .into_iter()
                .map(|s| s.signal)
                .collect()
        };
        assert!(fired("innerwarden mute ATR-001").contains(&"guard_self_disable".into()));
        assert!(
            fired("sudo systemctl stop innerwarden-sensor innerwarden-agent")
                .contains(&"security_tooling_tamper".into())
        );
        assert!(fired("cat ~/.ssh/id_rsa").contains(&"sensitive_credential_read".into()));
        let refusal = crate::file_tools::refusal_verdict("Edit", "/h/.claude/settings.json", "x");
        assert_eq!(refusal["signals"][0]["signal"], "privileged_file_write");

        // And the list has no entry the checks above did not cover.
        assert_eq!(EXTRA_HARD_SIGNALS.len(), 4);
        for signal in EXTRA_HARD_SIGNALS {
            assert!(is_hard_signal(signal));
        }
    }

    #[test]
    fn only_a_charged_hard_signal_reaches_the_hard_layer() {
        let analysis = |signals: Vec<(&str, u32)>| CommandAnalysis {
            command: "x".into(),
            risk_score: 0,
            severity: "low".into(),
            signals: signals
                .into_iter()
                .map(|(signal, score)| crate::mcp::AnalysisSignal {
                    signal: signal.into(),
                    score,
                    detail: String::new(),
                })
                .collect(),
            recommendation: "review".into(),
            explanation: String::new(),
            atr_matches: Vec::new(),
            asi_ids: Vec::new(),
        };
        assert!(hits_hard_layer(&analysis(vec![(
            "download_and_execute",
            40
        )])));
        assert!(hits_hard_layer(&analysis(vec![
            ("destructive_command", 10),
            ("guard_self_disable", 60)
        ])));
        // A subsumed duplicate scores 0 and does not count on its own.
        assert!(!hits_hard_layer(&analysis(vec![(
            "download_and_execute",
            0
        )])));
        assert!(!hits_hard_layer(&analysis(vec![(
            "destructive_command",
            90
        )])));
        assert!(!hits_hard_layer(&analysis(vec![])));
    }
}
