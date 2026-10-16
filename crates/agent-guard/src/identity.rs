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
//! This module is not wired into anything yet. Behaviour of the binary is
//! unchanged.

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

/// The directory, under the user's state home, where the launcher keeps one
/// record per instance OUTSIDE the jail (`<state home>/innerwarden/instances`).
pub const LAUNCHER_RECORD_DIR: &str = "innerwarden/instances";

/// The file name of an instance's record in a records directory, or `None` if
/// `instance_id` is not a well-formed id. An id is the only part of the name the
/// caller does not control, and it is checked before it can become a path.
pub fn instance_record_file(instance_id: &str) -> Option<String> {
    is_instance_id(instance_id).then(|| format!("{instance_id}.json"))
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

/// The schema number this build writes.
pub const LAUNCH_SCHEMA: u32 = 1;

/// The schema numbers this build reads: its own and the one before. Today there
/// is only one, so this is `[1]`; when a version 2 exists this lists both, and
/// the golden test for version 1 keeps proving the old one still parses.
pub const READABLE_SCHEMAS: &[u32] = &[1];

/// The largest record read. A record is a few hundred bytes; anything near this
/// is not one, and a reader that took more would let a writer cost it memory.
pub const MAX_RECORD_BYTES: usize = 16 * 1024;

const MAX_ID_LEN: usize = 64;
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
}

/// A dedicated scope the launcher put the jail in, when it could.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub unit: String,
    pub cgroup_path: String,
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
    pub scope: Option<Scope>,
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
    let readable = u32::try_from(schema)
        .ok()
        .is_some_and(|n| READABLE_SCHEMAS.contains(&n));
    if !readable {
        return Err(if schema > u64::from(LAUNCH_SCHEMA) {
            RecordError::NewerSchema(schema)
        } else {
            RecordError::UnsupportedSchema(schema)
        });
    }
    // Only schema 1 exists. A version 2 adds its own arm here, and keeps this
    // one for the records already written.
    let record: LaunchRecord =
        serde_json::from_slice(bytes).map_err(|e| RecordError::Malformed(e.to_string()))?;
    record.validate()?;
    Ok(record)
}

impl LaunchRecord {
    /// Whether every value is inside what its field may hold.
    pub fn validate(&self) -> Result<(), RecordError> {
        if self.schema != LAUNCH_SCHEMA {
            return Err(RecordError::Invalid(
                "schema is not the one this build writes",
            ));
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
        if let Some(scope) = &self.scope {
            if !is_unit_name(&scope.unit) {
                return Err(RecordError::Invalid("scope.unit"));
            }
            if !is_absolute_path(&scope.cgroup_path) {
                return Err(RecordError::Invalid("scope.cgroup_path"));
            }
        }
        Ok(())
    }
}

/// `[a-z0-9-]`, 1 to 64 bytes. It becomes a file name and a unit name, so no
/// dot, slash or case.
fn is_instance_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The same shape as the agent id a decision records: lowercase, digits, `-`
/// and `_`, up to 64 bytes.
fn is_agent_label(label: &str) -> bool {
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
}

/// Why [`judge_trust_in_jail`] gave the level it gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// Same namespace as the record, read-only record, trusted launcher.
    ConfinedByNamespace,
    /// Same namespace as the record, but the launcher is a file its user could
    /// have replaced (a per-user install).
    LauncherNotTrusted,
    NoRecord,
    RecordUnreadable,
    RecordWritable,
    /// The backend has no PID namespace to compare (macOS).
    NoNamespaceOnBackend,
    /// The record names the host's own namespace, so it describes no jail.
    HostNamespaceRecorded,
    OwnNamespaceUnreadable,
    NamespaceMismatch,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::ConfinedByNamespace => "confined_by_namespace",
            Reason::LauncherNotTrusted => "launcher_not_trusted",
            Reason::NoRecord => "no_record",
            Reason::RecordUnreadable => "record_unreadable",
            Reason::RecordWritable => "record_writable",
            Reason::NoNamespaceOnBackend => "no_namespace_on_backend",
            Reason::HostNamespaceRecorded => "host_namespace_recorded",
            Reason::OwnNamespaceUnreadable => "own_namespace_unreadable",
            Reason::NamespaceMismatch => "namespace_mismatch",
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
/// | 8 | same namespace, launcher not root-owned | observed | `LauncherNotTrusted` |
/// | 9 | same namespace, launcher root-owned | confined | `ConfinedByNamespace` |
///
/// Why each row is the way it is:
///
/// * 3: the namespace is readable by the agent, so a record it can write is a
///   record it can make say anything.
/// * 5: a launcher bug or a forged record naming the host's namespace would
///   otherwise make every process on the machine "match".
/// * 7: a record copied into a place the launcher never put it describes
///   another process's jail.
/// * 8 is a ceiling, not a bonus: with a launcher the user's own programs can
///   replace, the record proves where this process runs and not who built the
///   boundary. Nothing here reaches `confined` from a per-user install.
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
    if !record.launcher.root_owned {
        return (Trust::Observed, Reason::LauncherNotTrusted);
    }
    (Trust::Confined, Reason::ConfinedByNamespace)
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
/// the hard layer where a profile is applied, not here.
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
  "instance_id": "7f3a9c1e-42",
  "agent_type": "claude-code",
  "launcher": { "path": "/usr/local/bin/innerwarden", "version": "1.6.0", "root_owned": true },
  "uid": 1000,
  "project": "my-app",
  "mode": "enforce",
  "started_at": "2026-10-16T09:30:00Z",
  "jail": { "backend": "bwrap", "pid": 48211, "start_ticks": 9120344, "pid_ns": 4026532871 },
  "scope": {
    "unit": "innerwarden-contain-7f3a9c1e-42.scope",
    "cgroup_path": "/user.slice/user-1000.slice/user@1000.service/app.slice/innerwarden-contain-7f3a9c1e-42.scope"
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

    #[test]
    fn the_golden_v1_record_parses_and_round_trips() {
        let record = golden();
        assert_eq!(record.agent_type, "claude-code");
        assert_eq!(record.jail.pid_ns, 4026532871);
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
            ["backend", "pid", "pid_ns", "start_ticks"]
        );
        assert_eq!(keys(&value["scope"]), ["cgroup_path", "unit"]);
        // And no trust field: the file cannot say what level it earns.
        for banned in ["trust", "confined", "level", "token", "env", "argv", "key"] {
            assert!(value.get(banned).is_none(), "{banned}");
        }
    }

    #[test]
    fn a_newer_schema_is_refused_not_guessed() {
        let mut value = golden_json();
        value["schema"] = json!(2);
        assert_eq!(parse_value(&value), Err(RecordError::NewerSchema(2)));
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
        for path in [vec![], vec!["launcher"], vec!["jail"], vec!["scope"]] {
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
            ("scope.unit", vec!["scope", "unit"], json!("a/b.scope")),
            ("scope.unit", vec!["scope", "unit"], json!("")),
            (
                "scope.cgroup_path",
                vec!["scope", "cgroup_path"],
                json!("user.slice/x"),
            ),
            (
                "scope.cgroup_path",
                vec!["scope", "cgroup_path"],
                json!("/a/../b"),
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
                    other => other,
                })),
                "{field} = {bad}"
            );
        }
    }

    /// A backend with no PID namespace cannot claim one.
    #[test]
    fn a_sandbox_exec_record_carries_no_namespace() {
        let mut value = golden_json();
        value["jail"]["backend"] = json!("sandbox-exec");
        assert!(matches!(parse_value(&value), Err(RecordError::Invalid(_))));
        value["jail"]["pid_ns"] = json!(0);
        assert!(parse_value(&value).is_ok());
    }

    #[test]
    fn a_record_file_name_comes_only_from_a_well_formed_id() {
        assert_eq!(
            instance_record_file("7f3a9c1e-42").as_deref(),
            Some("7f3a9c1e-42.json")
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

    #[test]
    fn the_names_are_the_ones_the_launcher_and_hook_share() {
        assert_eq!(IDENTITY_FLAG, "--identity");
        assert_eq!(JAIL_RECORD_PATH, "/run/innerwarden/instance.json");
        assert_eq!(LAUNCHER_RECORD_DIR, "innerwarden/instances");
    }

    // -- trust inside the jail ---------------------------------------------

    const OWN_NS: u64 = 4026532871;

    fn facts<'a>(record: &'a LaunchRecord, read_only: bool, own: Option<u64>) -> InJailFacts<'a> {
        InJailFacts {
            record: RecordRead::Present { record, read_only },
            own_pid_ns: own,
        }
    }

    /// Row 9: the only way to `confined`.
    #[test]
    fn row_9_same_namespace_read_only_record_and_root_owned_launcher_is_confined() {
        let record = golden();
        assert_eq!(
            judge_trust_in_jail(facts(&record, true, Some(OWN_NS))),
            (Trust::Confined, Reason::ConfinedByNamespace)
        );
    }

    #[test]
    fn row_1_no_record_is_declared() {
        let judged = judge_trust_in_jail(InJailFacts {
            record: RecordRead::Absent,
            own_pid_ns: Some(OWN_NS),
        });
        assert_eq!(judged, (Trust::Declared, Reason::NoRecord));
    }

    #[test]
    fn row_2_an_unusable_record_is_declared() {
        let judged = judge_trust_in_jail(InJailFacts {
            record: RecordRead::Unreadable,
            own_pid_ns: Some(OWN_NS),
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

    /// Of every combination of the inputs, exactly one reaches `confined`.
    #[test]
    fn confined_is_reached_by_exactly_one_combination() {
        let mut confined = 0;
        for root_owned in [false, true] {
            for read_only in [false, true] {
                for own in [
                    None,
                    Some(OWN_NS),
                    Some(OWN_NS + 1),
                    Some(INITIAL_PID_NS_INODE),
                ] {
                    for backend_bwrap in [false, true] {
                        let mut record = golden();
                        record.launcher.root_owned = root_owned;
                        if !backend_bwrap {
                            record.jail.backend = JailBackend::SandboxExec;
                            record.jail.pid_ns = 0;
                        }
                        if judge_trust_in_jail(facts(&record, read_only, own)).0 == Trust::Confined
                        {
                            confined += 1;
                            assert!(
                                root_owned && read_only && backend_bwrap && own == Some(OWN_NS)
                            );
                        }
                    }
                }
            }
        }
        assert_eq!(confined, 1);
    }

    #[test]
    fn a_reason_is_spelled_the_same_in_serde_and_as_str() {
        for reason in [
            Reason::ConfinedByNamespace,
            Reason::LauncherNotTrusted,
            Reason::NoRecord,
            Reason::RecordUnreadable,
            Reason::RecordWritable,
            Reason::NoNamespaceOnBackend,
            Reason::HostNamespaceRecorded,
            Reason::OwnNamespaceUnreadable,
            Reason::NamespaceMismatch,
        ] {
            assert_eq!(
                serde_json::to_value(reason).unwrap(),
                json!(reason.as_str())
            );
        }
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
