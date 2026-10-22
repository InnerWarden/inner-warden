//! Profiles per type of agent: the third of the four rule layers.
//!
//! A profile says, for one type of agent (`claude-code`, `cursor`, ...), what
//! that agent may do beyond the general policy and what it may not. Every
//! decision here is pure: the caller reads the file, the verdict and the
//! instance's trust, and hands them in.
//!
//! # The file
//!
//! `agent-profiles.toml`, read from two places:
//!
//! * `/etc/innerwarden/agent-profiles.toml`, owned by root and writable by
//!   nobody else;
//! * `~/.config/innerwarden/agent-profiles.toml`, owned by the user and
//!   writable by nobody else (the guard refuses an agent's write into that
//!   directory).
//!
//! **With neither file, nothing in this module runs**: no layer is built, no
//! field is recorded, and every decision is the one the guard made before
//! profiles existed. With one or both, they are merged (see [`merge`]).
//!
//! **Only the system file relaxes.** An allowance (`allow_categories`,
//! `mcp_tools_allow`, `mode = "enforce"`) in the user's file is refused at
//! load ([`check_user_file`]). A relaxation is honoured only for a confined
//! instance, and inside the jail the user's `~/.config/innerwarden` is the
//! jail's own, which the agent can write; a file the agent's account can
//! write must never be able to loosen what that agent is held to. The user's
//! file can tighten, and can give `contain --identity` its jail settings.
//!
//! No reading from inside a jail is `confined`, so the hook decides a shell
//! command at `confined` only when the Active Defence agent on its host
//! answered that a relaxation applies ([`crate::identity::INSTANCE_DECIDE_ROUTE`]),
//! and then keeps the stricter of its own decision and the host's. The MCP
//! proxy and the file tools do not ask: there a relaxation is recorded and
//! not applied.
//!
//! ```toml
//! schema_version = 1
//!
//! [profile.claude-code]
//! mode = "block-review"                    # or "enforce"
//! allow_categories = ["bare_ip_fetch"]     # signal names, see below
//! deny_categories = ["cloud_control_plane"]
//! mcp_tools_allow = ["read_file"]
//! mcp_tools_deny = ["delete_file"]
//!
//! [profile.claude-code.jail]               # read by `contain --identity`
//! project_rw = "/srv/app"                  # the project, when --project is not given
//! extra_ro = ["/opt/sdk"]                  # more read-only paths inside the jail
//! deny_read = ["config/prod.yaml"]         # more project files hidden in the jail
//! net = true                               # the only value this version has
//! ```
//!
//! A file of `schema_version = 2` reads as one of schema 1 and adds one key
//! that only the system file may hold (see [`AskHost`]), and two jail
//! settings that either file may hold and the user's file can only tighten
//! (see [`JailStart`]):
//!
//! ```toml
//! schema_version = 2
//!
//! [profile.claude-code]
//! ask_host = "every_command"               # or "review", the default
//!
//! [profile.claude-code.jail]
//! start = "only_when_admitted"             # or "always", the default
//! hide_home = [".cache/git/credential"]    # home paths covered by an empty mount
//! ```
//!
//! `start` says when `contain --identity` starts the agent: `always`, or
//! `only_when_admitted`, only once Active Defence on this host has admitted
//! the jail (the launcher otherwise exits 2 and starts nothing). `hide_home`
//! names paths under the home, without `..`, that the jail covers with an
//! empty mount where they exist. Merged, the stricter `start` and every
//! hidden path of both files hold.
//!
//! `ask_host` says when the hook of an identified instance of the type asks
//! Active Defence on its host about a shell command: `review` (only a command
//! the general rules sent to review, what the hook always did) or
//! `every_command` (every command the hook does not refuse itself). The
//! user's file never says it, and a file of schema 1 that says it is refused:
//! a build that reads only schema 1 refuses the whole file, so `ask_host` is
//! never quietly dropped. Active Defence on the host reads the same file, so
//! every reader, it included, must be a version that reads schema 2 before a
//! file of schema 2 is written.
//!
//! A category is one of the signal names the engine raises
//! ([`crate::mcp::SIGNAL_NAMES`]). ATR categories are another namespace (they
//! are muted with `innerwarden mute`) and are refused here, as is any name
//! the engine does not raise: a rule that can never match is an error said at
//! load, never a rule that quietly matches nothing.
//!
//! # The four layers, and which one decides
//!
//! 1. **Hard** rules: the same everywhere, relaxed by nothing. The engine's
//!    floor ([`crate::mcp::AGENT_REVIEW_FLOOR`]), turning the guard off or
//!    writing into its configuration, removing the product, a file tool
//!    changing a privileged file, reading `~/.ssh`, `~/.aws` or `~/.gnupg`,
//!    and reaching the guard's own LLM key ([`crate::threats::names_guard_llm_key`]).
//!    An `allow_categories` entry that names one of these is refused at load.
//! 2. **General** policy: the engine (built-in checks and ATR rules), the
//!    person's own `suppress.toml`, the hook line's mode. For every agent.
//! 3. **Agent type**: the profile.
//! 4. **Instance**: an exception for one launch. This version has no store
//!    for one, so the layer never speaks.
//!
//! Precedence ([`crate::identity::decide`]): a hard refusal, then any `deny`
//! from any layer, then the `allow` of the narrowest layer, then the general
//! verdict.
//!
//! **A profile relaxes a `review`, never a refusal.** When the general layer
//! refuses a command (`deny`), no `allow_categories` entry lifts it, even for a
//! confined instance; a refusal is lifted only by the person, with
//! `innerwarden allow`. What an allow turns into `allow` is a command the
//! general layer held for review, and only when every signal it carries is in
//! the profile's `allow_categories`: one signal outside the list and the
//! review stands. An argument that arrived in an earlier tool result is never
//! relaxed.
//!
//! **A relaxation is honoured only for a confined instance.** The name an
//! agent declares (the `--agent` flag on its hook line, its environment, its
//! session id) is its own to choose, so a `declared` or `observed` agent that
//! names the most permissive type gets the general policy. A tightening (a
//! `deny_categories` or `mcp_tools_deny` entry, `mode = "block-review"`) holds
//! at any trust, since an agent gains nothing by being held to more; it is
//! keyed by the name the agent declares, so an agent outside a jail escapes
//! it by declaring another name and lands on the general policy, never below
//! it. `confined` is never what a hook reads from inside its own jail: that
//! reading tops at `observed` ([`crate::identity::judge_trust_in_jail`]), so
//! with nothing but the guard on the host a relaxation is recorded and never
//! honoured. It takes a witness outside the agent.
//!
//! `mode = "enforce"` on a hook line that blocks on review lets a review run
//! (a relaxation: confined only); `mode = "block-review"` makes a review block
//! (any trust). A hook line in monitor never blocks, whatever a profile says:
//! `innerwarden dry-run` is the person's switch, and a profile cannot make a
//! monitoring hook act. A profile cannot say `monitor` either: monitor never
//! blocks, so the hard rules would stop holding.
//!
//! In the MCP proxy the general layer has no review: a call is forwarded or
//! refused. So `mcp_tools_allow` lifts nothing there (a refused call stays
//! refused) and only `mcp_tools_deny` and `deny_categories` change what
//! happens. The proxy's own `--mode` still decides whether a refusal blocks:
//! `advisory` and `warn` forward it with an alert.
//!
//! # A file that cannot be used
//!
//! A file that does not parse, names an unknown key, category or mode, is not
//! the owner's, or can be written by someone else, is never half applied: the
//! hook refuses every shell command and the proxy every tool call (both say
//! why), until the file is fixed or removed. A monitoring hook and an
//! advisory proxy say so and let the call run. `contain --identity` refuses to
//! start.
//!
//! # What the person decided about a type of agent
//!
//! `[agent.<agent type>]` holds the decisions the `innerwarden agents
//! approve|profile|allow|revoke` verbs write (they edit the file in place and
//! keep its comments; see [`edit_approve`] and its neighbours):
//!
//! ```toml
//! [agent.claude-code]
//! lifecycle = "approved"                   # or "revoked"; absent = discovered
//! owner = "maria"
//! profile = "engineering"                  # a [profile.<name>] of THIS file, or "general"
//! approved_by = "maria"
//! approved_at = "2026-10-17T09:00:00Z"
//! revoked_instances = ["3f9a0c1e5b7d42a8c6e1f0b2d4a69c87"]
//! allow_categories = ["bare_ip_fetch"]     # allowed from a case, confined instances only
//! mcp_tools_allow = ["read_file"]
//!
//! [[agent.claude-code.exception]]          # one instance only, confined only
//! instance_id = "3f9a0c1e5b7d42a8c6e1f0b2d4a69c87"
//! category = "tmp_execution"               # or mcp_tool = "..."
//! ```
//!
//! * `profile` picks the rules a type gets: another table of the same file,
//!   or `general` for the general rules alone. With no `profile`, a type gets
//!   `[profile.<agent type>]` when there is one, as before.
//! * `allow_categories` and `mcp_tools_allow` here add to the type's profile;
//!   an `exception` is the fourth layer, one instance's own allowance. Both
//!   are relaxations: honoured only for a confined instance, refused at load
//!   in the user's file, and never a hard signal.
//! * A revoked type, or a revoked instance, is refused by the hard layer:
//!   "Refused: this agent was revoked." The entry stays, with who approved it
//!   and who revoked it, and nothing recorded about it is removed. The name
//!   is the one the agent declares, so an agent outside a jail that gives
//!   another name lands on the general rules, not on a refusal.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::identity::{
    decide, is_hard_signal, is_instance_id, Decision, LayerRule, Layers, Lifecycle, Trust, Verdict,
};
use crate::mcp::SIGNAL_NAMES;

/// The file's name, in both places.
pub const PROFILES_FILE: &str = "agent-profiles.toml";

/// The system-wide file.
pub const SYSTEM_PROFILES_PATH: &str = "/etc/innerwarden/agent-profiles.toml";

/// The user's file, relative to the home.
pub const USER_PROFILES_PATH: &str = ".config/innerwarden/agent-profiles.toml";

/// The schema a new file is written with: a file the verbs create, or one a
/// build that reads only this schema can read.
pub const PROFILES_SCHEMA: u32 = 1;

/// The schema that adds what only the system file says about a type, when its
/// hook asks the host ([`AskHost`]), and two jail settings: when the jail
/// starts ([`JailStart`]) and what of the home it hides.
pub const PROFILES_SCHEMA_2: u32 = 2;

/// Every schema this build reads. A file of schema 1 reads as it always did,
/// and a key schema 2 added is refused in it.
pub const READABLE_PROFILES_SCHEMAS: [u32; 2] = [PROFILES_SCHEMA, PROFILES_SCHEMA_2];

/// The largest file read. A file of profiles is a few kilobytes.
pub const MAX_PROFILES_BYTES: usize = 64 * 1024;

/// The `profile` an `[agent.<type>]` table names for the general rules alone.
/// No `[profile.general]` table may exist.
pub const GENERAL_PROFILE: &str = "general";

/// The longest owner or operator name.
pub const MAX_PERSON_NAME_CHARS: usize = 64;

const MAX_TYPES: usize = 64;
const MAX_ENTRIES: usize = 128;
const MAX_TOOL_NAME_BYTES: usize = 128;
const MAX_PATH_BYTES: usize = 4096;
const MAX_GLOB_BYTES: usize = 255;
const MAX_TIME_BYTES: usize = 64;

/// The most home paths one profile hides, and the longest one.
pub const MAX_HIDE_HOME: usize = 32;
const MAX_HIDE_HOME_BYTES: usize = 255;

// ---------------------------------------------------------------------------
// The file as written
// ---------------------------------------------------------------------------

/// The file as it parses, before any check.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfilesFile {
    pub schema_version: u32,
    #[serde(default)]
    pub profile: BTreeMap<String, ProfileEntry>,
    #[serde(default)]
    pub agent: BTreeMap<String, AgentEntry>,
}

/// One `[agent.<agent type>]` table as written: what the person decided
/// about that type.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEntry {
    #[serde(default)]
    pub lifecycle: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub approved_by: Option<String>,
    #[serde(default)]
    pub approved_at: Option<String>,
    #[serde(default)]
    pub revoked_by: Option<String>,
    #[serde(default)]
    pub revoked_at: Option<String>,
    #[serde(default)]
    pub revoked_instances: Vec<String>,
    #[serde(default)]
    pub allow_categories: Vec<String>,
    #[serde(default)]
    pub mcp_tools_allow: Vec<String>,
    #[serde(default)]
    pub exception: Vec<ExceptionEntry>,
}

/// One `[[agent.<agent type>.exception]]` entry as written: one allowance
/// for one instance.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionEntry {
    pub instance_id: String,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub mcp_tool: Option<String>,
}

/// One `[profile.<agent type>]` table as written.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileEntry {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub allow_categories: Vec<String>,
    #[serde(default)]
    pub deny_categories: Vec<String>,
    #[serde(default)]
    pub mcp_tools_allow: Vec<String>,
    #[serde(default)]
    pub mcp_tools_deny: Vec<String>,
    #[serde(default)]
    pub jail: Option<JailEntry>,
    /// Schema 2, system file only.
    #[serde(default)]
    pub ask_host: Option<String>,
}

/// One `[profile.<agent type>.jail]` table as written.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JailEntry {
    #[serde(default)]
    pub project_rw: Option<String>,
    #[serde(default)]
    pub extra_ro: Vec<String>,
    #[serde(default)]
    pub deny_read: Vec<String>,
    #[serde(default)]
    pub net: Option<bool>,
    /// Schema 2.
    #[serde(default)]
    pub start: Option<String>,
    /// Schema 2.
    #[serde(default)]
    pub hide_home: Vec<String>,
}

// ---------------------------------------------------------------------------
// The profiles as applied
// ---------------------------------------------------------------------------

/// How a profile wants a review treated on a hook line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProfileMode {
    /// A review runs; a refusal blocks.
    #[serde(rename = "enforce")]
    Enforce,
    /// A review blocks too.
    #[serde(rename = "block-review")]
    BlockReview,
}

impl ProfileMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ProfileMode::Enforce => "enforce",
            ProfileMode::BlockReview => "block-review",
        }
    }
}

/// When the hook of a type's identified instance asks Active Defence on its
/// host about a shell command ([`crate::identity::INSTANCE_DECIDE_ROUTE`]).
/// Said by `ask_host` in a profile of the system file, schema 2.
///
/// Whatever it says, a command the hook refuses itself (a hard rule, a
/// refusal of the general rules, a profile's own refusal) is never asked
/// about, and the hook keeps the stricter of its own verdict and the host's.
/// A command the general rules allow (by a suppression too) is made stricter
/// only by a refusal of the host's own
/// ([`crate::identity::InstanceDecideAnswer::refuses_on_its_own`]).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum AskHost {
    /// Only a command the general rules sent to review: what the hook always
    /// did, and what a profile without `ask_host` means.
    #[default]
    #[serde(rename = "review")]
    Review,
    /// Every shell command the hook does not refuse itself, an `allow` of the
    /// general rules too.
    #[serde(rename = "every_command")]
    EveryCommand,
}

impl AskHost {
    pub fn as_str(self) -> &'static str {
        match self {
            AskHost::Review => "review",
            AskHost::EveryCommand => "every_command",
        }
    }
}

/// When `contain --identity` starts the agent in its jail. Said by `start`
/// in a profile's jail table, schema 2.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum JailStart {
    /// Whatever the host said: what the launcher always did, and what a
    /// profile without `start` means.
    #[default]
    #[serde(rename = "always")]
    Always,
    /// Only once Active Defence on this host has admitted the jail. Without
    /// that admission the launcher starts nothing and exits 2. The stricter
    /// of the two: merged, it holds over `always`.
    #[serde(rename = "only_when_admitted")]
    OnlyWhenAdmitted,
}

impl JailStart {
    pub fn as_str(self) -> &'static str {
        match self {
            JailStart::Always => "always",
            JailStart::OnlyWhenAdmitted => "only_when_admitted",
        }
    }
}

/// The jail settings a profile gives `contain --identity`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JailProfile {
    /// The project mounted read-write, when no `--project` is given: an
    /// absolute path or one under `~/`.
    pub project_rw: Option<String>,
    /// More read-only paths inside the jail, absolute or under `~/`.
    pub extra_ro: Vec<String>,
    /// More project-relative globs hidden inside the jail, on top of the
    /// defaults and any `--deny-read`.
    pub deny_read: Vec<String>,
    /// When the jail starts; `None` is [`JailStart::Always`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<JailStart>,
    /// Paths under the home, relative to it, covered inside the jail by an
    /// empty mount where they exist.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hide_home: Vec<String>,
}

impl JailProfile {
    /// When the jail starts: [`JailStart::Always`] unless the profile says.
    pub fn start(&self) -> JailStart {
        self.start.unwrap_or_default()
    }
}

/// Which file a profile came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileSource {
    /// [`SYSTEM_PROFILES_PATH`].
    System,
    /// The user's own file.
    User,
}

impl ProfileSource {
    pub fn as_str(self) -> &'static str {
        match self {
            ProfileSource::System => "system",
            ProfileSource::User => "user",
        }
    }
}

/// One type's profile, checked. Every list is sorted and has no repeats.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentProfile {
    pub mode: Option<ProfileMode>,
    pub allow_categories: Vec<String>,
    pub deny_categories: Vec<String>,
    pub mcp_tools_allow: Vec<String>,
    pub mcp_tools_deny: Vec<String>,
    pub jail: JailProfile,
    /// When the hook asks the host ([`AskHost`]); `None` is
    /// [`AskHost::Review`]. Out of [`merge`], only ever the system file's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ask_host: Option<AskHost>,
    /// The file it came from, once [`merge`] has put the two together (the
    /// system file when both have it). `None` straight out of [`validate`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<ProfileSource>,
}

/// One instance's own allowances (the fourth layer), checked and sorted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceException {
    pub categories: Vec<String>,
    pub mcp_tools: Vec<String>,
}

/// What the person decided about one type of agent, checked. Lists sorted,
/// no repeats.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRecord {
    /// `None` until someone approves or revokes it: discovered.
    pub lifecycle: Option<Lifecycle>,
    pub owner: Option<String>,
    /// The profile assigned to the type: a profile's name, or
    /// [`GENERAL_PROFILE`]. `None`: the type's own `[profile.<type>]`, if any.
    pub profile: Option<String>,
    pub approved_by: Option<String>,
    pub approved_at: Option<String>,
    pub revoked_by: Option<String>,
    pub revoked_at: Option<String>,
    pub revoked_instances: Vec<String>,
    pub allow_categories: Vec<String>,
    pub mcp_tools_allow: Vec<String>,
    /// By instance id.
    pub exceptions: BTreeMap<String, InstanceException>,
}

impl AgentRecord {
    /// The lifecycle the record gives its type.
    pub fn lifecycle(&self) -> Lifecycle {
        self.lifecycle.unwrap_or(Lifecycle::Discovered)
    }
}

/// Every type's profile, checked, by agent type, and what the person decided
/// about each type.
///
/// Out of [`validate`], `types` are the file's tables as written; out of
/// [`merge`], each type's rules as they apply (its assigned profile and the
/// allowances added to it).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentProfiles {
    pub types: BTreeMap<String, AgentProfile>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub agents: BTreeMap<String, AgentRecord>,
}

/// Why a call is refused for a revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revocation {
    /// The whole type was revoked.
    AgentType,
    /// The calling instance was.
    Instance,
}

impl Revocation {
    /// The sentence the refusal carries.
    pub fn sentence(self) -> &'static str {
        match self {
            Revocation::AgentType => "Refused: this agent was revoked.",
            Revocation::Instance => "Refused: this instance was revoked.",
        }
    }
}

/// What the person's decisions say about one call: the facts the hard and
/// instance layers need, looked up once.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecordFacts<'a> {
    pub revoked: Option<Revocation>,
    /// The calling instance's own allowances.
    pub exception: Option<&'a InstanceException>,
}

impl AgentProfiles {
    /// The profile for `agent_type`, if there is one.
    pub fn get(&self, agent_type: &str) -> Option<&AgentProfile> {
        self.types.get(agent_type)
    }

    /// When the hook asks the host about a shell command of `agent_type`:
    /// what the profile in force for it says, [`AskHost::Review`] when it
    /// says nothing or there is none.
    pub fn ask_host(&self, agent_type: Option<&str>) -> AskHost {
        agent_type
            .and_then(|name| self.get(name))
            .and_then(|profile| profile.ask_host)
            .unwrap_or_default()
    }

    /// The decisions recorded about `agent_type`, if any.
    pub fn record(&self, agent_type: &str) -> Option<&AgentRecord> {
        self.agents.get(agent_type)
    }

    /// The lifecycle of `agent_type`: discovered when nothing was decided.
    pub fn lifecycle(&self, agent_type: &str) -> Lifecycle {
        self.record(agent_type)
            .map(AgentRecord::lifecycle)
            .unwrap_or(Lifecycle::Discovered)
    }

    /// Whether a call from `agent_type` (the name it declares, or the one its
    /// record names) and `instance_id` (set only when the hook's namespace
    /// matched its record) is refused for a revocation. An instance revoked
    /// under any type is refused under every type.
    pub fn revocation(
        &self,
        agent_type: Option<&str>,
        instance_id: Option<&str>,
    ) -> Option<Revocation> {
        if agent_type.is_some_and(|name| self.lifecycle(name) == Lifecycle::Revoked) {
            return Some(Revocation::AgentType);
        }
        let id = instance_id?;
        self.agents
            .values()
            .any(|record| record.revoked_instances.iter().any(|r| r == id))
            .then_some(Revocation::Instance)
    }

    /// The facts [`decide_shell_in`] and [`decide_tool_call_in`] take for one
    /// call.
    pub fn facts(&self, agent_type: Option<&str>, instance_id: Option<&str>) -> RecordFacts<'_> {
        let exception = agent_type
            .zip(instance_id)
            .and_then(|(name, id)| self.record(name)?.exceptions.get(id));
        RecordFacts {
            revoked: self.revocation(agent_type, instance_id),
            exception,
        }
    }
}

/// Why a file of profiles cannot be used, in words for the person who wrote
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileError(pub String);

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ProfileError {}

fn error_at(agent_type: &str, field: &str, why: impl fmt::Display) -> ProfileError {
    ProfileError(format!("profile `{agent_type}`: {field}: {why}"))
}

/// Read a file's bytes into the profiles it applies: [`MAX_PROFILES_BYTES`] at
/// most, UTF-8, TOML with no unknown key, then [`validate`].
pub fn parse(bytes: &[u8]) -> Result<AgentProfiles, ProfileError> {
    if bytes.len() > MAX_PROFILES_BYTES {
        return Err(ProfileError(format!(
            "larger than the {MAX_PROFILES_BYTES} bytes a file of profiles may hold"
        )));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| ProfileError("not UTF-8 text".to_string()))?;
    let file: ProfilesFile = toml::from_str(text)
        .map_err(|error| ProfileError(format!("not a profiles file: {error}")))?;
    validate(file)
}

/// Check a parsed file and turn it into the profiles it applies.
///
/// Refused, with the reason: a schema this build does not read, an agent type
/// that is not an agent id, a mode other than `enforce` or `block-review`, a
/// category that is not a signal name, an allowed category that is a hard
/// rule, a category or a tool both allowed and denied, a tool name or a path
/// that is not one, `net = false`, and a key of schema 2 in a file of schema
/// 1.
pub fn validate(file: ProfilesFile) -> Result<AgentProfiles, ProfileError> {
    if !READABLE_PROFILES_SCHEMAS.contains(&file.schema_version) {
        return Err(ProfileError(format!(
            "unsupported schema_version {} (this version reads {PROFILES_SCHEMA} and \
             {PROFILES_SCHEMA_2})",
            file.schema_version
        )));
    }
    if file.profile.len() > MAX_TYPES {
        return Err(ProfileError(format!(
            "{} profiles, more than the {MAX_TYPES} a file may hold",
            file.profile.len()
        )));
    }
    if file.agent.len() > MAX_TYPES {
        return Err(ProfileError(format!(
            "{} agent tables, more than the {MAX_TYPES} a file may hold",
            file.agent.len()
        )));
    }
    let names: BTreeSet<String> = file.profile.keys().cloned().collect();
    let mut types = BTreeMap::new();
    for (agent_type, entry) in file.profile {
        if !crate::hook::is_agent_id(&agent_type) {
            return Err(ProfileError(format!(
                "`{agent_type}` is not an agent type: lowercase letters, digits, `-` and `_`, \
                 at most 64"
            )));
        }
        if agent_type == GENERAL_PROFILE {
            return Err(ProfileError(format!(
                "`[profile.{GENERAL_PROFILE}]`: `{GENERAL_PROFILE}` names your general rules, \
                 so no profile may take that name"
            )));
        }
        let profile = validate_entry(&agent_type, entry, file.schema_version)?;
        types.insert(agent_type, profile);
    }
    let mut agents = BTreeMap::new();
    for (agent_type, entry) in file.agent {
        if !crate::hook::is_agent_id(&agent_type) {
            return Err(ProfileError(format!(
                "`[agent.{agent_type}]`: not an agent type: lowercase letters, digits, `-` and \
                 `_`, at most 64"
            )));
        }
        let record = validate_agent(&agent_type, entry, &names)?;
        agents.insert(agent_type, record);
    }
    Ok(AgentProfiles { types, agents })
}

fn agent_error(agent_type: &str, field: &str, why: impl fmt::Display) -> ProfileError {
    ProfileError(format!("agent `{agent_type}`: {field}: {why}"))
}

/// A person's name as the file keeps it: 1 to 64 characters, no control
/// character.
pub fn is_person_name(name: &str) -> bool {
    !name.trim().is_empty()
        && name.chars().count() <= MAX_PERSON_NAME_CHARS
        && !name.chars().any(char::is_control)
}

fn person(
    agent_type: &str,
    field: &str,
    value: Option<String>,
) -> Result<Option<String>, ProfileError> {
    match value {
        Some(name) if !is_person_name(&name) => Err(agent_error(
            agent_type,
            field,
            format!("{name:?} is not a name (1 to {MAX_PERSON_NAME_CHARS} characters, no control character)"),
        )),
        other => Ok(other),
    }
}

fn moment(
    agent_type: &str,
    field: &str,
    value: Option<String>,
) -> Result<Option<String>, ProfileError> {
    match value {
        Some(at)
            if at.len() > MAX_TIME_BYTES || chrono::DateTime::parse_from_rfc3339(&at).is_err() =>
        {
            Err(agent_error(
                agent_type,
                field,
                format!("{at:?} is not an RFC 3339 time"),
            ))
        }
        other => Ok(other),
    }
}

fn allowed_categories(
    agent_type: &str,
    field: &str,
    list: Vec<String>,
) -> Result<Vec<String>, ProfileError> {
    let list = categories(agent_type, field, list)?;
    if let Some(hard) = list.iter().find(|c| is_hard_signal(c)) {
        return Err(error_at(
            agent_type,
            field,
            format!("`{hard}` is a hard rule: nothing relaxes it"),
        ));
    }
    Ok(list)
}

fn validate_agent(
    agent_type: &str,
    entry: AgentEntry,
    profiles: &BTreeSet<String>,
) -> Result<AgentRecord, ProfileError> {
    let lifecycle = match entry.lifecycle.as_deref() {
        None => None,
        Some("approved") => Some(Lifecycle::Approved),
        Some("revoked") => Some(Lifecycle::Revoked),
        Some(other) => {
            return Err(agent_error(
                agent_type,
                "lifecycle",
                format!("unknown lifecycle `{other}` (use `approved` or `revoked`; a type nobody decided about has none)"),
            ))
        }
    };
    if let Some(name) = &entry.profile {
        if name != GENERAL_PROFILE && !profiles.contains(name) {
            return Err(agent_error(
                agent_type,
                "profile",
                format!(
                    "`{name}` names no [profile.{name}] in this file (use `{GENERAL_PROFILE}` for \
                     the general rules)"
                ),
            ));
        }
    }
    bounded(agent_type, "revoked_instances", &entry.revoked_instances)?;
    if let Some(id) = entry
        .revoked_instances
        .iter()
        .find(|id| !is_instance_id(id))
    {
        return Err(agent_error(
            agent_type,
            "revoked_instances",
            format!("{id:?} is not an instance id"),
        ));
    }
    let allow_categories =
        allowed_categories(agent_type, "allow_categories", entry.allow_categories)?;
    let mcp_tools_allow = tools(agent_type, "mcp_tools_allow", entry.mcp_tools_allow)?;
    bounded_entries(agent_type, "exception", entry.exception.len())?;
    let mut exceptions: BTreeMap<String, InstanceException> = BTreeMap::new();
    for exception in entry.exception {
        if !is_instance_id(&exception.instance_id) {
            return Err(agent_error(
                agent_type,
                "exception.instance_id",
                format!("{:?} is not an instance id", exception.instance_id),
            ));
        }
        let slot = exceptions.entry(exception.instance_id).or_default();
        match (exception.category, exception.mcp_tool) {
            (Some(category), None) => {
                let mut checked =
                    allowed_categories(agent_type, "exception.category", vec![category])?;
                slot.categories.append(&mut checked);
            }
            (None, Some(tool)) => {
                let mut checked = tools(agent_type, "exception.mcp_tool", vec![tool])?;
                slot.mcp_tools.append(&mut checked);
            }
            _ => {
                return Err(agent_error(
                    agent_type,
                    "exception",
                    "each exception names exactly one `category` or one `mcp_tool`",
                ))
            }
        }
    }
    for slot in exceptions.values_mut() {
        slot.categories = sorted(std::mem::take(&mut slot.categories));
        slot.mcp_tools = sorted(std::mem::take(&mut slot.mcp_tools));
    }
    Ok(AgentRecord {
        lifecycle,
        owner: person(agent_type, "owner", entry.owner)?,
        profile: entry.profile,
        approved_by: person(agent_type, "approved_by", entry.approved_by)?,
        approved_at: moment(agent_type, "approved_at", entry.approved_at)?,
        revoked_by: person(agent_type, "revoked_by", entry.revoked_by)?,
        revoked_at: moment(agent_type, "revoked_at", entry.revoked_at)?,
        revoked_instances: sorted(entry.revoked_instances),
        allow_categories,
        mcp_tools_allow,
        exceptions,
    })
}

fn bounded_entries(agent_type: &str, field: &str, len: usize) -> Result<(), ProfileError> {
    if len > MAX_ENTRIES {
        return Err(agent_error(
            agent_type,
            field,
            format!("{len} entries, more than {MAX_ENTRIES}"),
        ));
    }
    Ok(())
}

/// `ask_host`, from a file of `schema`: refused in a file of schema 1, one of
/// the two words in one of schema 2.
fn validate_ask_host(
    agent_type: &str,
    value: Option<&str>,
    schema: u32,
) -> Result<Option<AskHost>, ProfileError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if schema < PROFILES_SCHEMA_2 {
        return Err(error_at(
            agent_type,
            "ask_host",
            format!("needs schema_version = {PROFILES_SCHEMA_2}"),
        ));
    }
    match value {
        "review" => Ok(Some(AskHost::Review)),
        "every_command" => Ok(Some(AskHost::EveryCommand)),
        other => Err(error_at(
            agent_type,
            "ask_host",
            format!("unknown value `{other}` (use `review` or `every_command`)"),
        )),
    }
}

fn validate_entry(
    agent_type: &str,
    entry: ProfileEntry,
    schema: u32,
) -> Result<AgentProfile, ProfileError> {
    let ask_host = validate_ask_host(agent_type, entry.ask_host.as_deref(), schema)?;
    let mode = match entry.mode.as_deref() {
        None => None,
        Some("enforce") => Some(ProfileMode::Enforce),
        Some("block-review") => Some(ProfileMode::BlockReview),
        Some("monitor") => {
            return Err(error_at(
                agent_type,
                "mode",
                "`monitor` is not a profile mode: monitor never blocks, so the hard rules \
                 would stop holding. Use `innerwarden dry-run` to stop blocking",
            ))
        }
        Some(other) => {
            return Err(error_at(
                agent_type,
                "mode",
                format!("unknown mode `{other}` (use `enforce` or `block-review`)"),
            ))
        }
    };
    let allow_categories = categories(agent_type, "allow_categories", entry.allow_categories)?;
    let deny_categories = categories(agent_type, "deny_categories", entry.deny_categories)?;
    if let Some(hard) = allow_categories.iter().find(|c| is_hard_signal(c)) {
        return Err(error_at(
            agent_type,
            "allow_categories",
            format!("`{hard}` is a hard rule: no profile relaxes it"),
        ));
    }
    if let Some(both) = allow_categories
        .iter()
        .find(|c| deny_categories.contains(c))
    {
        return Err(error_at(
            agent_type,
            "allow_categories",
            format!("`{both}` is both allowed and denied"),
        ));
    }
    let mcp_tools_allow = tools(agent_type, "mcp_tools_allow", entry.mcp_tools_allow)?;
    let mcp_tools_deny = tools(agent_type, "mcp_tools_deny", entry.mcp_tools_deny)?;
    if let Some(both) = mcp_tools_allow.iter().find(|t| mcp_tools_deny.contains(t)) {
        return Err(error_at(
            agent_type,
            "mcp_tools_allow",
            format!("`{both}` is both allowed and denied"),
        ));
    }
    let jail = match entry.jail {
        None => JailProfile::default(),
        Some(jail) => validate_jail(agent_type, jail, schema)?,
    };
    Ok(AgentProfile {
        mode,
        allow_categories,
        deny_categories,
        mcp_tools_allow,
        mcp_tools_deny,
        jail,
        ask_host,
        source: None,
    })
}

fn bounded(agent_type: &str, field: &str, list: &[String]) -> Result<(), ProfileError> {
    if list.len() > MAX_ENTRIES {
        return Err(error_at(
            agent_type,
            field,
            format!("{} entries, more than {MAX_ENTRIES}", list.len()),
        ));
    }
    Ok(())
}

fn sorted(mut list: Vec<String>) -> Vec<String> {
    list.sort();
    list.dedup();
    list
}

fn categories(
    agent_type: &str,
    field: &str,
    list: Vec<String>,
) -> Result<Vec<String>, ProfileError> {
    bounded(agent_type, field, &list)?;
    for name in &list {
        if SIGNAL_NAMES.contains(&name.as_str()) {
            continue;
        }
        if name.starts_with("atr:") {
            return Err(error_at(
                agent_type,
                field,
                format!(
                    "`{name}` is an ATR category; those are muted with `innerwarden mute`, \
                     a profile names the engine's signals"
                ),
            ));
        }
        return Err(error_at(
            agent_type,
            field,
            format!(
                "`{name}` is not a signal name. A category is one of: {}",
                SIGNAL_NAMES.join(", ")
            ),
        ));
    }
    Ok(sorted(list))
}

fn tools(agent_type: &str, field: &str, list: Vec<String>) -> Result<Vec<String>, ProfileError> {
    bounded(agent_type, field, &list)?;
    for name in &list {
        if name.is_empty()
            || name.len() > MAX_TOOL_NAME_BYTES
            || name.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(error_at(
                agent_type,
                field,
                format!(
                    "{name:?} is not a tool name (1 to {MAX_TOOL_NAME_BYTES} bytes, no spaces)"
                ),
            ));
        }
    }
    Ok(sorted(list))
}

/// An absolute path, or one under `~/`, with no `.` or `..` step.
fn is_jail_path(path: &str) -> bool {
    let rest = if let Some(rest) = path.strip_prefix("~/") {
        rest
    } else if let Some(rest) = path.strip_prefix('/') {
        rest
    } else {
        return false;
    };
    path.len() <= MAX_PATH_BYTES
        && !path.chars().any(char::is_control)
        && rest
            .split('/')
            .filter(|step| !step.is_empty())
            .all(|step| step != "." && step != "..")
}

/// A path under the home, relative to it: one or more plain steps (no `.`,
/// `..` or empty step, no glob), no control character, at most 255 bytes.
fn is_home_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_HIDE_HOME_BYTES
        && !path.starts_with(['/', '~'])
        && !path
            .chars()
            .any(|c| c.is_control() || matches!(c, '*' | '?' | '[' | ']'))
        && path
            .split('/')
            .all(|step| !step.is_empty() && step != "." && step != "..")
}

/// `start`, from a file of `schema`: refused in a file of schema 1, one of
/// the two words in one of schema 2.
fn validate_jail_start(
    agent_type: &str,
    value: Option<&str>,
    schema: u32,
) -> Result<Option<JailStart>, ProfileError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if schema < PROFILES_SCHEMA_2 {
        return Err(error_at(
            agent_type,
            "jail.start",
            format!("needs schema_version = {PROFILES_SCHEMA_2}"),
        ));
    }
    match value {
        "always" => Ok(Some(JailStart::Always)),
        "only_when_admitted" => Ok(Some(JailStart::OnlyWhenAdmitted)),
        other => Err(error_at(
            agent_type,
            "jail.start",
            format!("unknown value `{other}` (use `always` or `only_when_admitted`)"),
        )),
    }
}

/// `hide_home`, from a file of `schema`: refused in a file of schema 1;
/// at most [`MAX_HIDE_HOME`] paths under the home ([`is_home_path`]).
fn validate_hide_home(
    agent_type: &str,
    list: Vec<String>,
    schema: u32,
) -> Result<Vec<String>, ProfileError> {
    if list.is_empty() {
        return Ok(list);
    }
    if schema < PROFILES_SCHEMA_2 {
        return Err(error_at(
            agent_type,
            "jail.hide_home",
            format!("needs schema_version = {PROFILES_SCHEMA_2}"),
        ));
    }
    if list.len() > MAX_HIDE_HOME {
        return Err(error_at(
            agent_type,
            "jail.hide_home",
            format!("{} entries, more than {MAX_HIDE_HOME}", list.len()),
        ));
    }
    if let Some(path) = list.iter().find(|p| !is_home_path(p)) {
        return Err(error_at(
            agent_type,
            "jail.hide_home",
            format!(
                "{path:?} is not a path under the home: written relative to it, without `.`, \
                 `..`, an empty step or a glob, at most {MAX_HIDE_HOME_BYTES} bytes"
            ),
        ));
    }
    Ok(sorted(list))
}

/// A glob relative to the project, with no `..` step.
fn is_project_glob(glob: &str) -> bool {
    !glob.is_empty()
        && glob.len() <= MAX_GLOB_BYTES
        && !glob.starts_with(['/', '~'])
        && !glob.chars().any(char::is_control)
        && glob.split('/').all(|step| step != "..")
}

fn validate_jail(
    agent_type: &str,
    jail: JailEntry,
    schema: u32,
) -> Result<JailProfile, ProfileError> {
    let start = validate_jail_start(agent_type, jail.start.as_deref(), schema)?;
    let hide_home = validate_hide_home(agent_type, jail.hide_home, schema)?;
    if jail.net == Some(false) {
        return Err(error_at(
            agent_type,
            "jail.net",
            "`net = false` is not available: the jail shares the host network in this version",
        ));
    }
    if let Some(project) = &jail.project_rw {
        if !is_jail_path(project) {
            return Err(error_at(
                agent_type,
                "jail.project_rw",
                format!("{project:?} is not an absolute path or one under `~/`"),
            ));
        }
    }
    bounded(agent_type, "jail.extra_ro", &jail.extra_ro)?;
    if let Some(path) = jail.extra_ro.iter().find(|p| !is_jail_path(p)) {
        return Err(error_at(
            agent_type,
            "jail.extra_ro",
            format!("{path:?} is not an absolute path or one under `~/`"),
        ));
    }
    bounded(agent_type, "jail.deny_read", &jail.deny_read)?;
    if let Some(glob) = jail.deny_read.iter().find(|g| !is_project_glob(g)) {
        return Err(error_at(
            agent_type,
            "jail.deny_read",
            format!("{glob:?} is not a glob relative to the project"),
        ));
    }
    Ok(JailProfile {
        project_rw: jail.project_rw,
        extra_ro: sorted(jail.extra_ro),
        deny_read: sorted(jail.deny_read),
        start,
        hide_home,
    })
}

/// Refuse a relaxation in the user's file (see the module notes): an
/// `allow_categories` or `mcp_tools_allow` entry, `mode = "enforce"`, or, in
/// an `[agent.<type>]` table, an allowance or an instance exception. A
/// profile the user's file assigns is one of its own tables, so it cannot
/// relax either.
///
/// `ask_host` is refused there whatever it says: when the hook asks the host
/// is the system file's to say, and inside the jail the user's file is one
/// the agent can write. The jail's `start` and `hide_home` are taken from
/// it: [`merge`] keeps the stricter `start` and every hidden path, so the
/// user's file can only tighten them.
pub fn check_user_file(profiles: &AgentProfiles) -> Result<(), ProfileError> {
    if let Some(agent_type) = profiles
        .types
        .iter()
        .find_map(|(name, profile)| profile.ask_host.map(|_| name))
    {
        return Err(error_at(
            agent_type,
            "ask_host",
            format!("only {SYSTEM_PROFILES_PATH} says when the hook asks the host"),
        ));
    }
    for (agent_type, record) in &profiles.agents {
        let field = if !record.allow_categories.is_empty() {
            "allow_categories"
        } else if !record.mcp_tools_allow.is_empty() {
            "mcp_tools_allow"
        } else if !record.exceptions.is_empty() {
            "exception"
        } else {
            continue;
        };
        return Err(agent_error(
            agent_type,
            field,
            format!(
                "only {SYSTEM_PROFILES_PATH} may relax a rule; the user's file can approve, \
                 revoke, and assign a profile of its own"
            ),
        ));
    }
    for (agent_type, profile) in &profiles.types {
        let field = if !profile.allow_categories.is_empty() {
            "allow_categories"
        } else if !profile.mcp_tools_allow.is_empty() {
            "mcp_tools_allow"
        } else if profile.mode == Some(ProfileMode::Enforce) {
            "mode"
        } else {
            continue;
        };
        return Err(error_at(
            agent_type,
            field,
            format!(
                "only {SYSTEM_PROFILES_PATH} may relax a rule; the user's file can only \
                 tighten (deny_categories, mcp_tools_deny, mode = \"block-review\") and set \
                 the jail"
            ),
        ));
    }
    Ok(())
}

/// The profiles of the two files, as one.
///
/// Nothing either file denies is lost: denials and hidden paths are the union
/// of both, and the mode is the stricter one. Allowances come from the system
/// file only ([`check_user_file`] refuses them in the other), and a category
/// the system file allows and the user's file denies is denied when a
/// decision is made. The project is the user's file's when it names one.
///
/// Each file is first resolved on its own ([`resolved_types`]): a type's
/// assigned profile replaces its own table, and the allowances its
/// `[agent.<type>]` table adds are put on it. A user's file that assigns
/// `general` therefore cannot take away what the system file gives: it adds
/// nothing, and the system file's rules for the type stand.
///
/// What was decided about a type is merged too: revoked if either file says
/// so, approved if either does, the system file's names and times first,
/// every revoked instance and every exception of both.
///
/// `ask_host` is the system file's alone: one in the user's file (which
/// [`check_user_file`] refuses) is never taken. The jail's `start` is the
/// stricter of the two files' and its hidden home paths those of both.
pub fn merge(system: Option<&AgentProfiles>, user: Option<&AgentProfiles>) -> AgentProfiles {
    let mut types: BTreeMap<String, AgentProfile> = BTreeMap::new();
    let sides = [
        system.map(|p| resolved_types(p, ProfileSource::System)),
        user.map(|p| resolved_types(p, ProfileSource::User)),
    ];
    for resolved in sides.iter().flatten() {
        for (agent_type, profile) in resolved {
            let merged = types.entry(agent_type.clone()).or_default();
            if merged.source.is_none() {
                merged.source = profile.source;
            }
            merged.mode = merged.mode.max(profile.mode);
            let union = |left: &[String], right: &[String]| {
                sorted(left.iter().chain(right).cloned().collect())
            };
            merged.allow_categories = union(&merged.allow_categories, &profile.allow_categories);
            merged.deny_categories = union(&merged.deny_categories, &profile.deny_categories);
            merged.mcp_tools_allow = union(&merged.mcp_tools_allow, &profile.mcp_tools_allow);
            merged.mcp_tools_deny = union(&merged.mcp_tools_deny, &profile.mcp_tools_deny);
            if profile.jail.project_rw.is_some() {
                merged.jail.project_rw = profile.jail.project_rw.clone();
            }
            merged.jail.extra_ro = union(&merged.jail.extra_ro, &profile.jail.extra_ro);
            merged.jail.deny_read = union(&merged.jail.deny_read, &profile.jail.deny_read);
            merged.jail.hide_home = union(&merged.jail.hide_home, &profile.jail.hide_home);
            merged.jail.start = merged.jail.start.max(profile.jail.start);
            if profile.source == Some(ProfileSource::System) {
                merged.ask_host = profile.ask_host;
            }
        }
    }
    let mut agents: BTreeMap<String, AgentRecord> = BTreeMap::new();
    for profiles in [system, user].into_iter().flatten() {
        for (agent_type, record) in &profiles.agents {
            let merged = agents.entry(agent_type.clone()).or_default();
            merge_record(merged, record);
        }
    }
    AgentProfiles { types, agents }
}

/// Fold `next` (the user's file's record, after the system file's) into
/// `merged`.
fn merge_record(merged: &mut AgentRecord, next: &AgentRecord) {
    let union = |left: &[String], right: &[String]| -> Vec<String> {
        sorted(left.iter().chain(right).cloned().collect())
    };
    merged.lifecycle = match (merged.lifecycle, next.lifecycle) {
        (Some(Lifecycle::Revoked), _) | (_, Some(Lifecycle::Revoked)) => Some(Lifecycle::Revoked),
        (Some(Lifecycle::Approved), _) | (_, Some(Lifecycle::Approved)) => {
            Some(Lifecycle::Approved)
        }
        _ => None,
    };
    let first = |left: &mut Option<String>, right: &Option<String>| {
        if left.is_none() {
            left.clone_from(right);
        }
    };
    first(&mut merged.owner, &next.owner);
    first(&mut merged.profile, &next.profile);
    first(&mut merged.approved_by, &next.approved_by);
    first(&mut merged.approved_at, &next.approved_at);
    if merged.revoked_by.is_none() && merged.revoked_at.is_none() {
        merged.revoked_by.clone_from(&next.revoked_by);
        merged.revoked_at.clone_from(&next.revoked_at);
    }
    merged.revoked_instances = union(&merged.revoked_instances, &next.revoked_instances);
    merged.allow_categories = union(&merged.allow_categories, &next.allow_categories);
    merged.mcp_tools_allow = union(&merged.mcp_tools_allow, &next.mcp_tools_allow);
    for (id, exception) in &next.exceptions {
        let slot = merged.exceptions.entry(id.clone()).or_default();
        slot.categories = union(&slot.categories, &exception.categories);
        slot.mcp_tools = union(&slot.mcp_tools, &exception.mcp_tools);
    }
}

/// One file's rules by type, as they apply: a type's assigned profile in
/// place of its own table (none for [`GENERAL_PROFILE`]), and the allowances
/// of its `[agent.<type>]` table added. Every profile is marked with `source`.
pub fn resolved_types(
    profiles: &AgentProfiles,
    source: ProfileSource,
) -> BTreeMap<String, AgentProfile> {
    let mut types = profiles.types.clone();
    for (agent_type, record) in &profiles.agents {
        let mut base = match record.profile.as_deref() {
            None => profiles.types.get(agent_type).cloned(),
            Some(GENERAL_PROFILE) => None,
            Some(name) => profiles.types.get(name).cloned(),
        };
        if !record.allow_categories.is_empty() || !record.mcp_tools_allow.is_empty() {
            let profile = base.get_or_insert_with(AgentProfile::default);
            profile.allow_categories = sorted(
                profile
                    .allow_categories
                    .iter()
                    .chain(&record.allow_categories)
                    .cloned()
                    .collect(),
            );
            profile.mcp_tools_allow = sorted(
                profile
                    .mcp_tools_allow
                    .iter()
                    .chain(&record.mcp_tools_allow)
                    .cloned()
                    .collect(),
            );
        }
        match base {
            Some(profile) => {
                types.insert(agent_type.clone(), profile);
            }
            None => {
                types.remove(agent_type);
            }
        }
    }
    for profile in types.values_mut() {
        profile.source = Some(source);
    }
    types
}

// ---------------------------------------------------------------------------
// Decisions
// ---------------------------------------------------------------------------

/// What a profile says about a screened command, from the signals the engine
/// CHARGED it with (a subsumed duplicate scored 0 is not one).
///
/// `deny` when any of them is in `deny_categories`. `allow` when there is at
/// least one and every one is in `allow_categories`: a signal the profile does
/// not name (an ATR category, a fetch-and-execute factor, a hard rule) keeps
/// the review. Otherwise nothing.
pub fn command_rule(profile: &AgentProfile, charged: &[&str]) -> Option<LayerRule> {
    let listed = |list: &[String], name: &str| list.iter().any(|entry| entry == name);
    if charged
        .iter()
        .any(|name| listed(&profile.deny_categories, name))
    {
        return Some(LayerRule::Deny);
    }
    if !charged.is_empty()
        && charged
            .iter()
            .all(|name| listed(&profile.allow_categories, name))
    {
        return Some(LayerRule::Allow);
    }
    None
}

/// What a profile says about an MCP tool call: `deny` for a tool in
/// `mcp_tools_deny` or a charged signal in `deny_categories`, `allow` for a
/// tool in `mcp_tools_allow` whose charged signals, if any, are all in
/// `allow_categories`. Tool names match exactly, as the server receives them.
pub fn tool_rule(profile: &AgentProfile, tool: &str, charged: &[&str]) -> Option<LayerRule> {
    let listed = |list: &[String], name: &str| list.iter().any(|entry| entry == name);
    if listed(&profile.mcp_tools_deny, tool)
        || charged
            .iter()
            .any(|name| listed(&profile.deny_categories, name))
    {
        return Some(LayerRule::Deny);
    }
    if listed(&profile.mcp_tools_allow, tool)
        && charged
            .iter()
            .all(|name| listed(&profile.allow_categories, name))
    {
        return Some(LayerRule::Allow);
    }
    None
}

/// Whether a review blocks on a hook line, with a profile's mode applied.
///
/// `block-review` makes it block at any trust; `enforce` lets it run only
/// for a confined instance, since that is a relaxation of a line that blocks
/// on review. No mode: the line's own.
pub fn review_blocks(line_block_review: bool, mode: Option<ProfileMode>, trust: Trust) -> bool {
    match mode {
        Some(ProfileMode::BlockReview) => true,
        Some(ProfileMode::Enforce) if trust == Trust::Confined => false,
        _ => line_block_review,
    }
}

/// One screened shell command, as the hook knows it after the general layer.
#[derive(Debug, Clone, Copy)]
pub struct ShellCall<'a> {
    /// The general layer's verdict (engine, the person's suppressions, the
    /// second opinion, an argument that came from a tool result).
    pub general: Verdict,
    /// The signals it was charged with.
    pub charged: &'a [&'a str],
    /// The general layer blocks it on this hook line, as the hook did before
    /// profiles: a refusal, or a review on a line that blocks reviews or with
    /// a floor signal.
    pub blocks_today: bool,
    /// The command reaches the guard's LLM key
    /// ([`crate::threats::names_guard_llm_key`]).
    pub names_llm_key: bool,
    /// An argument of it arrived in an earlier tool result.
    pub tainted: bool,
}

/// What the hook does with one command once the profile is applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellOutcome {
    pub decision: Decision,
    /// The hook refuses it (outside monitor).
    pub blocks: bool,
    /// One line on what the layers did that the general verdict does not
    /// say, for the record and the agent; `None` when the general verdict
    /// stands as it was.
    pub note: Option<String>,
    /// The profile or the exception would have allowed it, the instance did
    /// not run confined, and the general rules decided.
    pub relaxation_withheld: bool,
}

fn verdict_word(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Allow => "allow",
        Verdict::Review => "review",
        Verdict::Deny => "deny",
    }
}

/// Decide a shell command with the layers.
///
/// `profile` is the agent type and its profile, `None` when the type has
/// none. The hard layer refuses what the general layer already blocks when
/// it carries a hard signal, and anything that reaches the guard's LLM key.
/// With no profile and no LLM key, the outcome is exactly the general
/// layer's: what the hook did before profiles.
pub fn decide_shell(
    call: &ShellCall<'_>,
    profile: Option<(&str, &AgentProfile)>,
    line_block_review: bool,
    trust: Trust,
) -> ShellOutcome {
    decide_shell_in(
        call,
        profile,
        RecordFacts::default(),
        line_block_review,
        trust,
    )
}

/// What an instance's exception says about a screened command: `allow` when
/// it carries at least one signal and the exception lists every one, as for
/// a profile's `allow_categories`. An exception never denies.
pub fn exception_command_rule(
    exception: &InstanceException,
    charged: &[&str],
) -> Option<LayerRule> {
    (!charged.is_empty()
        && charged
            .iter()
            .all(|name| exception.categories.iter().any(|entry| entry == name)))
    .then_some(LayerRule::Allow)
}

/// [`decide_shell`] with the person's decisions about the caller: a
/// revocation is a hard refusal, and the calling instance's exception is the
/// instance layer (an allowance, so [`decide`] honours it for a confined
/// instance only).
pub fn decide_shell_in(
    call: &ShellCall<'_>,
    profile: Option<(&str, &AgentProfile)>,
    record: RecordFacts<'_>,
    line_block_review: bool,
    trust: Trust,
) -> ShellOutcome {
    let hard_signal = call.blocks_today && call.charged.iter().any(|s| is_hard_signal(s));
    let agent_type = profile
        .and_then(|(_, p)| command_rule(p, call.charged))
        .filter(|rule| !(call.tainted && *rule == LayerRule::Allow));
    let instance = record
        .exception
        .and_then(|exception| exception_command_rule(exception, call.charged))
        .filter(|_| !call.tainted);
    let layers = Layers {
        hard_refused: call.names_llm_key || hard_signal || record.revoked.is_some(),
        general: call.general,
        agent_type,
        instance,
    };
    let decision = decide(layers, trust);
    let relaxation_withheld = relaxation_withheld(layers, trust, decision);
    let review = review_blocks(line_block_review, profile.and_then(|(_, p)| p.mode), trust);
    let blocks = match decision.verdict {
        Verdict::Deny => true,
        Verdict::Review => review,
        Verdict::Allow => false,
    };
    let name = profile.map(|(name, _)| name).unwrap_or("");
    let note = match (decision.deciding_layer, decision.verdict) {
        (crate::identity::RuleLayer::Hard, _) if record.revoked.is_some() && !hard_signal => {
            record.revoked.map(|r| r.sentence().to_string())
        }
        (crate::identity::RuleLayer::Hard, _) if call.names_llm_key && !hard_signal => {
            Some("hard rule: the command reaches the guard's own LLM key".to_string())
        }
        (crate::identity::RuleLayer::Instance, Verdict::Allow) => Some(format!(
            "an exception for this confined instance allows {}",
            call.charged.join(", ")
        )),
        (crate::identity::RuleLayer::AgentType, Verdict::Deny) => {
            let denied = profile
                .map(|(_, p)| {
                    call.charged
                        .iter()
                        .filter(|s| p.deny_categories.iter().any(|d| d == *s))
                        .copied()
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            Some(format!("the `{name}` agent profile denies {denied}"))
        }
        (crate::identity::RuleLayer::AgentType, Verdict::Allow) => Some(format!(
            "the `{name}` agent profile allows {} for this confined instance",
            call.charged.join(", ")
        )),
        (_, Verdict::Review) if review != line_block_review => Some(if review {
            format!("the `{name}` agent profile holds a review to block")
        } else {
            format!("the `{name}` agent profile lets a review run for this confined instance")
        }),
        _ => None,
    };
    ShellOutcome {
        decision,
        blocks,
        note,
        relaxation_withheld,
    }
}

/// Whether the profile or the instance's exception would have allowed what
/// the general rules decided, had the instance run confined: the case the
/// screen words as "would allow this, but this instance does not run
/// confined". Computed beside [`decide`], which is left as it is.
pub fn relaxation_withheld(layers: Layers, trust: Trust, decision: Decision) -> bool {
    if trust == Trust::Confined || decision.deciding_layer != crate::identity::RuleLayer::General {
        return false;
    }
    let confined = decide(layers, Trust::Confined);
    confined.verdict == Verdict::Allow
        && matches!(
            confined.deciding_layer,
            crate::identity::RuleLayer::AgentType | crate::identity::RuleLayer::Instance
        )
}

/// The word a decision's verdict is recorded with (`allow`, `review`,
/// `deny`), the engine's own spelling.
pub fn recommendation(decision: &Decision) -> &'static str {
    verdict_word(decision.verdict)
}

/// One client `tools/call` the MCP proxy inspected, as the general layer left
/// it.
#[derive(Debug, Clone, Copy)]
pub struct ToolCallFacts<'a> {
    /// The tool's name, as the server receives it.
    pub tool: &'a str,
    /// The general layer forwards it.
    pub allowed: bool,
    /// The general layer raised a finding about it.
    pub has_alerts: bool,
    /// For a shell tool, the signals its command was charged with.
    pub charged: &'a [&'a str],
    /// The general layer refused it by a rule of the hard layer (a change to a
    /// privileged file, a read of a secret store).
    pub hard_alert: bool,
    /// The call reaches the guard's LLM key.
    pub names_llm_key: bool,
}

/// What the proxy does with one tool call once the profile is applied:
/// the decision, and why when the profile or the hard layer changed it.
pub fn decide_tool_call(
    call: &ToolCallFacts<'_>,
    profile: Option<(&str, &AgentProfile)>,
    trust: Trust,
) -> (Decision, Option<String>) {
    decide_tool_call_in(call, profile, None, trust)
}

/// [`decide_tool_call`] with a revocation of the caller, which is a hard
/// refusal. The proxy has no review to relax, so an instance's exception
/// changes nothing there and is not taken.
pub fn decide_tool_call_in(
    call: &ToolCallFacts<'_>,
    profile: Option<(&str, &AgentProfile)>,
    revoked: Option<Revocation>,
    trust: Trust,
) -> (Decision, Option<String>) {
    let general = if !call.allowed {
        Verdict::Deny
    } else if call.has_alerts {
        Verdict::Review
    } else {
        Verdict::Allow
    };
    let hard_rule =
        !call.allowed && (call.hard_alert || call.charged.iter().any(|s| is_hard_signal(s)));
    let agent_type = profile.and_then(|(_, p)| tool_rule(p, call.tool, call.charged));
    let decision = decide(
        Layers {
            hard_refused: call.names_llm_key || hard_rule || revoked.is_some(),
            general,
            agent_type,
            instance: None,
        },
        trust,
    );
    let name = profile.map(|(name, _)| name).unwrap_or("");
    let note = match (decision.deciding_layer, decision.verdict) {
        (crate::identity::RuleLayer::Hard, _) if revoked.is_some() && !hard_rule => {
            revoked.map(|r| r.sentence().to_string())
        }
        (crate::identity::RuleLayer::Hard, _) if call.names_llm_key && !hard_rule => {
            Some("hard rule: the call reaches the guard's own LLM key".to_string())
        }
        (crate::identity::RuleLayer::AgentType, Verdict::Deny) => Some(format!(
            "the `{name}` agent profile denies the tool `{}`",
            call.tool
        )),
        _ => None,
    };
    (decision, note)
}

/// What the MCP proxy applies, set once when it starts.
// One value per proxy run, never held in a collection: the size of a profile
// in it costs nothing worth a box at every place that builds or matches it.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyProfile {
    /// Profiles are in force. `profile` is the one for the proxy's agent type
    /// (`None` when it has none: the hard layer still holds), `trust` the
    /// level the proxy knows its instance at.
    Active {
        agent_type: Option<String>,
        profile: Option<AgentProfile>,
        trust: Trust,
        /// The type or the instance was revoked when the proxy started:
        /// every tool call is refused by the hard layer.
        revoked: Option<Revocation>,
    },
    /// A file of profiles is there and cannot be used: every tool call is
    /// refused with this reason, which the proxy's mode then applies.
    Invalid { why: String },
}

// ---------------------------------------------------------------------------
// What changed, for the audit line
// ---------------------------------------------------------------------------

/// One change between two sets of profiles: what happened, to which type, and
/// the value it happened to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileChange {
    /// The layer the change is to: `agent_type` for a profile, a type's
    /// lifecycle or its assignment, `instance` for one instance's exception
    /// or revocation.
    pub layer: crate::identity::RuleLayer,
    pub action: String,
    pub agent_type: String,
    pub value: String,
}

impl ProfileChange {
    /// A change to a type's profile.
    pub fn to_type(action: &str, agent_type: &str, value: &str) -> Self {
        ProfileChange {
            layer: crate::identity::RuleLayer::AgentType,
            action: action.to_string(),
            agent_type: agent_type.to_string(),
            value: value.to_string(),
        }
    }
}

/// Every change from `before` to `after`, additions and removals both, so the
/// line stream can be replayed into what was in force at any moment.
pub fn changes(before: &AgentProfiles, after: &AgentProfiles) -> Vec<ProfileChange> {
    let mut out = Vec::new();
    let empty = AgentProfile::default();
    let mut push = |action: &str, agent_type: &str, value: &str| {
        out.push(ProfileChange::to_type(action, agent_type, value));
    };
    let mut names: Vec<&String> = before.types.keys().chain(after.types.keys()).collect();
    names.sort();
    names.dedup();
    for name in names {
        let (old, new) = (before.types.get(name), after.types.get(name));
        match (old, new) {
            (None, Some(_)) => push("profile_added", name, ""),
            (Some(_), None) => push("profile_removed", name, ""),
            _ => {}
        }
        let (old, new) = (old.unwrap_or(&empty), new.unwrap_or(&empty));
        if old.mode != new.mode {
            push(
                "mode_changed",
                name,
                new.mode.map(ProfileMode::as_str).unwrap_or(""),
            );
        }
        if old.jail.project_rw != new.jail.project_rw {
            push(
                "jail_project_rw_changed",
                name,
                new.jail.project_rw.as_deref().unwrap_or(""),
            );
        }
        if old.ask_host != new.ask_host {
            push(
                "ask_host_changed",
                name,
                new.ask_host.map(AskHost::as_str).unwrap_or(""),
            );
        }
        if old.jail.start != new.jail.start {
            push(
                "jail_start_changed",
                name,
                new.jail.start.map(JailStart::as_str).unwrap_or(""),
            );
        }
        let lists: [(&str, &[String], &[String]); 7] = [
            (
                "allow_category",
                &old.allow_categories,
                &new.allow_categories,
            ),
            ("deny_category", &old.deny_categories, &new.deny_categories),
            ("mcp_tool_allow", &old.mcp_tools_allow, &new.mcp_tools_allow),
            ("mcp_tool_deny", &old.mcp_tools_deny, &new.mcp_tools_deny),
            ("jail_extra_ro", &old.jail.extra_ro, &new.jail.extra_ro),
            ("jail_deny_read", &old.jail.deny_read, &new.jail.deny_read),
            ("jail_hide_home", &old.jail.hide_home, &new.jail.hide_home),
        ];
        for (label, old, new) in lists {
            for added in new.iter().filter(|v| !old.contains(v)) {
                push(&format!("{label}_added"), name, added);
            }
            for removed in old.iter().filter(|v| !new.contains(v)) {
                push(&format!("{label}_removed"), name, removed);
            }
        }
    }
    record_changes(before, after, &mut out);
    out
}

/// The changes to what was decided about each type: its lifecycle and its
/// assignment (layer `agent_type`), and each instance's revocation and
/// exceptions (layer `instance`, the value `<instance id> <what>`).
fn record_changes(before: &AgentProfiles, after: &AgentProfiles, out: &mut Vec<ProfileChange>) {
    use crate::identity::RuleLayer;
    let empty = AgentRecord::default();
    let mut names: Vec<&String> = before.agents.keys().chain(after.agents.keys()).collect();
    names.sort();
    names.dedup();
    for name in names {
        let old = before.agents.get(name).unwrap_or(&empty);
        let new = after.agents.get(name).unwrap_or(&empty);
        let mut push = |layer: RuleLayer, action: &str, value: &str| {
            out.push(ProfileChange {
                layer,
                action: action.to_string(),
                agent_type: name.clone(),
                value: value.to_string(),
            });
        };
        if old.lifecycle() != new.lifecycle() {
            push(
                RuleLayer::AgentType,
                "lifecycle_changed",
                new.lifecycle().as_str(),
            );
        }
        if old.profile != new.profile {
            push(
                RuleLayer::AgentType,
                "profile_assigned",
                new.profile.as_deref().unwrap_or(""),
            );
        }
        for id in new
            .revoked_instances
            .iter()
            .filter(|id| !old.revoked_instances.contains(id))
        {
            push(RuleLayer::Instance, "instance_revoked", id);
        }
        for id in old
            .revoked_instances
            .iter()
            .filter(|id| !new.revoked_instances.contains(id))
        {
            push(RuleLayer::Instance, "instance_revocation_removed", id);
        }
        let none = InstanceException::default();
        let mut ids: Vec<&String> = old.exceptions.keys().chain(new.exceptions.keys()).collect();
        ids.sort();
        ids.dedup();
        for id in ids {
            let was = old.exceptions.get(id).unwrap_or(&none);
            let is = new.exceptions.get(id).unwrap_or(&none);
            for (label, was, is) in [
                ("category", &was.categories, &is.categories),
                ("mcp_tool", &was.mcp_tools, &is.mcp_tools),
            ] {
                for added in is.iter().filter(|v| !was.contains(v)) {
                    push(
                        RuleLayer::Instance,
                        &format!("exception_{label}_added"),
                        &format!("{id} {added}"),
                    );
                }
                for removed in was.iter().filter(|v| !is.contains(v)) {
                    push(
                        RuleLayer::Instance,
                        &format!("exception_{label}_removed"),
                        &format!("{id} {removed}"),
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// What a profile says, and whether a change widens it
// ---------------------------------------------------------------------------

/// The profile's rules as short sentences, for a person choosing one. `None`
/// is the general rules alone.
pub fn describe(profile: Option<&AgentProfile>) -> Vec<String> {
    let Some(profile) = profile else {
        return vec!["Your general rules, nothing added.".to_string()];
    };
    let mut out = Vec::new();
    let list = |out: &mut Vec<String>, label: &str, items: &[String]| {
        if !items.is_empty() {
            out.push(format!("{label}: {}.", items.join(", ")));
        }
    };
    list(
        &mut out,
        "Runs without review, when confined",
        &profile.allow_categories,
    );
    list(&mut out, "Refused", &profile.deny_categories);
    list(
        &mut out,
        "MCP tools let through, when confined",
        &profile.mcp_tools_allow,
    );
    list(&mut out, "MCP tools refused", &profile.mcp_tools_deny);
    match profile.mode {
        Some(ProfileMode::BlockReview) => out.push("A review is refused too.".to_string()),
        Some(ProfileMode::Enforce) => {
            out.push("A review runs, when confined.".to_string());
        }
        None => {}
    }
    if let Some(project) = &profile.jail.project_rw {
        out.push(format!("Project folder read-write in the jail: {project}."));
    }
    list(&mut out, "Read-only in the jail", &profile.jail.extra_ro);
    list(&mut out, "Hidden in the jail", &profile.jail.deny_read);
    list(
        &mut out,
        "Hidden from the home in the jail",
        &profile.jail.hide_home,
    );
    if profile.jail.start() == JailStart::OnlyWhenAdmitted {
        out.push("The jail starts only when Active Defence on this host admits it.".to_string());
    }
    if profile.ask_host == Some(AskHost::EveryCommand) {
        out.push(
            "In a jail, Active Defence on this host is asked about every shell command, not \
             only a review."
                .to_string(),
        );
    }
    if out.is_empty() {
        out.push("Your general rules, nothing added.".to_string());
    }
    out
}

/// How strict a mode is: a review refused, the line's own, a review run.
fn mode_strictness(mode: Option<ProfileMode>) -> u8 {
    match mode {
        Some(ProfileMode::BlockReview) => 2,
        None => 1,
        Some(ProfileMode::Enforce) => 0,
    }
}

/// Whether going from `before` to `after` (`None`: the general rules) lets
/// the agent do anything it could not: an allowance added, a refusal or a
/// hidden path taken away (of the project or of the home), a looser mode,
/// more read-only paths in the jail, another project folder, a jail that
/// starts without the host's admission where it did not, or the host asked
/// about every command where it was not (the host then decides commands it
/// was never asked about, and it may allow what it is asked).
pub fn relaxes(before: Option<&AgentProfile>, after: Option<&AgentProfile>) -> bool {
    let empty = AgentProfile::default();
    let (before, after) = (before.unwrap_or(&empty), after.unwrap_or(&empty));
    let gains = |old: &[String], new: &[String]| new.iter().any(|v| !old.contains(v));
    gains(&before.allow_categories, &after.allow_categories)
        || gains(&before.mcp_tools_allow, &after.mcp_tools_allow)
        || gains(&after.deny_categories, &before.deny_categories)
        || gains(&after.mcp_tools_deny, &before.mcp_tools_deny)
        || mode_strictness(after.mode) < mode_strictness(before.mode)
        || gains(&before.jail.extra_ro, &after.jail.extra_ro)
        || gains(&after.jail.deny_read, &before.jail.deny_read)
        || gains(&after.jail.hide_home, &before.jail.hide_home)
        || after.jail.start() < before.jail.start()
        || (after.jail.project_rw.is_some() && after.jail.project_rw != before.jail.project_rw)
        || (after.ask_host == Some(AskHost::EveryCommand)
            && before.ask_host != Some(AskHost::EveryCommand))
}

// ---------------------------------------------------------------------------
// Writing a decision into the file
// ---------------------------------------------------------------------------

/// Who made a change and when (RFC 3339), as the file records it.
#[derive(Debug, Clone, Copy)]
pub struct Stamp<'a> {
    pub by: &'a str,
    pub at: &'a str,
}

/// One allowance a case can add: a signal name, or an MCP tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum AllowRule {
    Category(String),
    McpTool(String),
}

impl AllowRule {
    pub fn value(&self) -> &str {
        match self {
            AllowRule::Category(value) | AllowRule::McpTool(value) => value,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            AllowRule::Category(_) => "category",
            AllowRule::McpTool(_) => "mcp_tool",
        }
    }
}

fn edit_error(why: impl fmt::Display) -> ProfileError {
    ProfileError(format!("the file cannot be edited: {why}"))
}

/// The file's text as an editable document; an absent or empty file is a new
/// one with this build's schema.
fn document(text: &str) -> Result<toml_edit::DocumentMut, ProfileError> {
    if text.trim().is_empty() {
        let mut doc = toml_edit::DocumentMut::new();
        doc["schema_version"] = toml_edit::value(i64::from(PROFILES_SCHEMA));
        return Ok(doc);
    }
    text.parse::<toml_edit::DocumentMut>().map_err(edit_error)
}

/// The `[agent.<agent_type>]` table, made when missing.
fn agent_table<'d>(
    doc: &'d mut toml_edit::DocumentMut,
    agent_type: &str,
) -> Result<&'d mut toml_edit::Table, ProfileError> {
    if !crate::hook::is_agent_id(agent_type) {
        return Err(edit_error(format!("`{agent_type}` is not an agent type")));
    }
    let agents = doc.entry("agent").or_insert_with(|| {
        let mut table = toml_edit::Table::new();
        table.set_implicit(true);
        toml_edit::Item::Table(table)
    });
    let agents = agents
        .as_table_mut()
        .ok_or_else(|| edit_error("`agent` is not written as tables"))?;
    agents
        .entry(agent_type)
        .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()))
        .as_table_mut()
        .ok_or_else(|| edit_error(format!("`agent.{agent_type}` is not written as a table")))
}

/// Add `value` to the array `key` of `table` unless it is there already.
fn push_unique(table: &mut toml_edit::Table, key: &str, value: &str) -> Result<(), ProfileError> {
    let item = table
        .entry(key)
        .or_insert_with(|| toml_edit::value(toml_edit::Array::new()));
    let array = item
        .as_array_mut()
        .ok_or_else(|| edit_error(format!("`{key}` is not a list")))?;
    if !array.iter().any(|v| v.as_str() == Some(value)) {
        array.push(value);
    }
    Ok(())
}

/// Approve `agent_type`: its lifecycle, who approved it and when, and the
/// owner and profile when given (`Some(GENERAL_PROFILE)` for the general
/// rules). Returns the file's new text; nothing else in it changes. The
/// caller checks the result with [`parse`] before writing it.
pub fn edit_approve(
    text: &str,
    agent_type: &str,
    owner: Option<&str>,
    profile: Option<&str>,
    stamp: Stamp<'_>,
) -> Result<String, ProfileError> {
    let mut doc = document(text)?;
    let table = agent_table(&mut doc, agent_type)?;
    table["lifecycle"] = toml_edit::value("approved");
    if let Some(owner) = owner {
        table["owner"] = toml_edit::value(owner);
    }
    if let Some(profile) = profile {
        table["profile"] = toml_edit::value(profile);
    }
    table["approved_by"] = toml_edit::value(stamp.by);
    table["approved_at"] = toml_edit::value(stamp.at);
    Ok(doc.to_string())
}

/// Assign `profile` (a profile's name, or [`GENERAL_PROFILE`]) to
/// `agent_type`.
pub fn set_assignment(text: &str, agent_type: &str, profile: &str) -> Result<String, ProfileError> {
    let mut doc = document(text)?;
    agent_table(&mut doc, agent_type)?["profile"] = toml_edit::value(profile);
    Ok(doc.to_string())
}

/// Add one allowance: to the type (`instance` `None`), or as an exception
/// for one instance.
pub fn add_allow(
    text: &str,
    agent_type: &str,
    rule: &AllowRule,
    instance: Option<&str>,
) -> Result<String, ProfileError> {
    let mut doc = document(text)?;
    let table = agent_table(&mut doc, agent_type)?;
    let Some(id) = instance else {
        let key = match rule {
            AllowRule::Category(_) => "allow_categories",
            AllowRule::McpTool(_) => "mcp_tools_allow",
        };
        push_unique(table, key, rule.value())?;
        return Ok(doc.to_string());
    };
    let exceptions = table
        .entry("exception")
        .or_insert_with(|| toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new()))
        .as_array_of_tables_mut()
        .ok_or_else(|| edit_error("`exception` is not a list of tables"))?;
    let exists = exceptions.iter().any(|entry| {
        entry.get("instance_id").and_then(|v| v.as_str()) == Some(id)
            && entry.get(rule.kind()).and_then(|v| v.as_str()) == Some(rule.value())
    });
    if !exists {
        let mut entry = toml_edit::Table::new();
        entry["instance_id"] = toml_edit::value(id);
        entry[rule.kind()] = toml_edit::value(rule.value());
        exceptions.push(entry);
    }
    Ok(doc.to_string())
}

/// Revoke the type (`instance` `None`), keeping who approved it, its owner,
/// profile and exceptions; or add one instance to its revoked instances.
pub fn revoke(
    text: &str,
    agent_type: &str,
    instance: Option<&str>,
    stamp: Stamp<'_>,
) -> Result<String, ProfileError> {
    let mut doc = document(text)?;
    let table = agent_table(&mut doc, agent_type)?;
    match instance {
        Some(id) => push_unique(table, "revoked_instances", id)?,
        None => {
            table["lifecycle"] = toml_edit::value("revoked");
            table["revoked_by"] = toml_edit::value(stamp.by);
            table["revoked_at"] = toml_edit::value(stamp.at);
        }
    }
    Ok(doc.to_string())
}

/// The folder under the home where an agent type's own installer keeps the
/// versions of the agent it runs, written as a profile writes a jail path.
/// A profile that holds the jail to the versions as they were installed
/// names it in `extra_ro`, so the jail sees them read-only even inside a
/// folder the jail may write. `None` for a type whose installer keeps none
/// there.
pub fn runtime_versions_dir(agent_type: &str) -> Option<&'static str> {
    match agent_type {
        "claude-code" => Some("~/.local/share/claude/versions"),
        _ => None,
    }
}

/// The dotdirs under a home that a Linux jail of `innerwarden contain`
/// never binds, so never shows: they hold keys, cloud credentials and mail.
/// A macOS jail denies only [`JAIL_HIDDEN_MACOS_DOTDIRS`] of them.
pub const JAIL_HIDDEN_DOTDIRS: &[&str] = &[".ssh", ".gnupg", ".aws", ".mozilla", ".thunderbird"];

/// The dotdirs under a home that a macOS jail's sandbox denies reading. It
/// lets the agent read everywhere else, so a macOS jail shows `~/.mozilla`
/// and `~/.thunderbird` (where Firefox and Thunderbird keep nothing on
/// macOS: their profiles are in `~/Library`).
pub const JAIL_HIDDEN_MACOS_DOTDIRS: &[&str] = &[".ssh", ".aws", ".gnupg"];

/// InnerWarden's own folder under a home, which no jail ever shows: it
/// holds the person's key and settings.
pub const JAIL_HIDDEN_CONFIG_DIR: &str = ".config/innerwarden";

/// The folders under a macOS home that a macOS jail denies reading: the
/// person's mail, messages and browser data.
pub const JAIL_HIDDEN_MACOS_HOME: &[&str] = &["Library/Mail", "Library/Messages", "Library/Safari"];

/// The places under `home` that a jail of `innerwarden contain` hides by
/// name, on macOS (`macos`) or Linux, each joined to `home`. Linux: each of
/// [`JAIL_HIDDEN_DOTDIRS`] and [`JAIL_HIDDEN_CONFIG_DIR`] (the jail's home
/// is an empty folder of its own, so it shows no other folder of the home
/// unless it binds it, and these it never binds). macOS: each of
/// [`JAIL_HIDDEN_MACOS_DOTDIRS`], [`JAIL_HIDDEN_CONFIG_DIR`] and
/// [`JAIL_HIDDEN_MACOS_HOME`]; the sandbox lets the agent read everywhere
/// else. Where a link there leads is the launcher's to find on the host,
/// and it hides that place too. Read this list rather than keep a copy of
/// it: a copy goes stale.
pub fn jail_hides_on(home: &std::path::Path, macos: bool) -> Vec<std::path::PathBuf> {
    let (dotdirs, more): (&[&str], &[&str]) = if macos {
        (JAIL_HIDDEN_MACOS_DOTDIRS, JAIL_HIDDEN_MACOS_HOME)
    } else {
        (JAIL_HIDDEN_DOTDIRS, &[])
    };
    dotdirs
        .iter()
        .chain(std::iter::once(&JAIL_HIDDEN_CONFIG_DIR))
        .chain(more)
        .map(|name| home.join(name))
        .collect()
}

/// Every place under `home` that [`jail_hides_on`] names on either OS,
/// each once, joined to `home` as named: [`JAIL_HIDDEN_DOTDIRS`],
/// [`JAIL_HIDDEN_CONFIG_DIR`] and [`JAIL_HIDDEN_MACOS_HOME`]. These are the
/// places no project or worktree of a jail may overlap, on any OS (on macOS
/// that is stricter than what its jail hides: it shows `~/.mozilla` and
/// `~/.thunderbird`). It is not what a jail of one OS hides: that is
/// [`jail_hides_on`].
pub fn jail_never_shows(home: &std::path::Path) -> Vec<std::path::PathBuf> {
    JAIL_HIDDEN_DOTDIRS
        .iter()
        .chain(std::iter::once(&JAIL_HIDDEN_CONFIG_DIR))
        .chain(JAIL_HIDDEN_MACOS_HOME)
        .map(|name| home.join(name))
        .collect()
}

/// A list of a profile's jail table that [`set_jail_path`] edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JailList {
    /// `extra_ro`: an absolute path or one under `~/`.
    ExtraRo,
    /// `hide_home`: a path under the home, relative to it (schema 2).
    HideHome,
}

impl JailList {
    fn key(self) -> &'static str {
        match self {
            JailList::ExtraRo => "extra_ro",
            JailList::HideHome => "hide_home",
        }
    }
}

/// The `[profile.<agent_type>.jail]` table, made when missing. Refused when
/// `[agent.<agent_type>]` assigns the type another profile: that profile's
/// rules apply to it, and an edit of its own table would change nothing.
fn jail_table<'d>(
    doc: &'d mut toml_edit::DocumentMut,
    agent_type: &str,
) -> Result<&'d mut toml_edit::Table, ProfileError> {
    if !crate::hook::is_agent_id(agent_type) {
        return Err(edit_error(format!("`{agent_type}` is not an agent type")));
    }
    let assigned = doc
        .get("agent")
        .and_then(|agents| agents.get(agent_type))
        .and_then(|table| table.get("profile"))
        .and_then(|profile| profile.as_str())
        .filter(|profile| *profile != agent_type)
        .map(str::to_string);
    if let Some(profile) = assigned {
        return Err(edit_error(format!(
            "`agent.{agent_type}` assigns the profile `{profile}`, whose rules apply to it; \
             edit that profile"
        )));
    }
    let implicit = || {
        let mut table = toml_edit::Table::new();
        table.set_implicit(true);
        toml_edit::Item::Table(table)
    };
    let profiles = doc
        .entry("profile")
        .or_insert_with(implicit)
        .as_table_mut()
        .ok_or_else(|| edit_error("`profile` is not written as tables"))?;
    profiles
        .entry(agent_type)
        .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()))
        .as_table_mut()
        .ok_or_else(|| edit_error(format!("`profile.{agent_type}` is not written as a table")))?
        .entry("jail")
        .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()))
        .as_table_mut()
        .ok_or_else(|| {
            edit_error(format!(
                "`profile.{agent_type}.jail` is not written as a table"
            ))
        })
}

/// Raise the file to [`PROFILES_SCHEMA_2`] when it is of an older schema:
/// the keys it adds are refused in a file of schema 1.
fn at_least_schema_2(doc: &mut toml_edit::DocumentMut) {
    let schema = doc
        .get("schema_version")
        .and_then(|v| v.as_integer())
        .unwrap_or(0);
    if schema < i64::from(PROFILES_SCHEMA_2) {
        doc["schema_version"] = toml_edit::value(i64::from(PROFILES_SCHEMA_2));
    }
}

/// Set when `agent_type`'s jail starts (`start`), raising the file to
/// schema 2 when it is older. Nothing else in it changes. The caller checks
/// the result with [`parse`] before writing it.
pub fn set_jail_start(
    text: &str,
    agent_type: &str,
    start: JailStart,
) -> Result<String, ProfileError> {
    let mut doc = document(text)?;
    jail_table(&mut doc, agent_type)?["start"] = toml_edit::value(start.as_str());
    at_least_schema_2(&mut doc);
    Ok(doc.to_string())
}

/// Add `path` to `agent_type`'s jail `list` (`present`) or take it out of it,
/// raising the file to schema 2 for a hidden home path. A path that is not
/// one the list takes is refused. Nothing else in the file changes. The
/// caller checks the result with [`parse`] before writing it.
pub fn set_jail_path(
    text: &str,
    agent_type: &str,
    list: JailList,
    path: &str,
    present: bool,
) -> Result<String, ProfileError> {
    let fits = match list {
        JailList::ExtraRo => is_jail_path(path),
        JailList::HideHome => is_home_path(path),
    };
    if !fits {
        return Err(edit_error(format!(
            "{path:?} is not a path `{}` takes",
            list.key()
        )));
    }
    let mut doc = document(text)?;
    let table = jail_table(&mut doc, agent_type)?;
    if present {
        push_unique(table, list.key(), path)?;
    } else if let Some(item) = table.get_mut(list.key()) {
        let array = item
            .as_array_mut()
            .ok_or_else(|| edit_error(format!("`{}` is not a list", list.key())))?;
        array.retain(|v| v.as_str() != Some(path));
    }
    if list == JailList::HideHome {
        at_least_schema_2(&mut doc);
    }
    Ok(doc.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::RuleLayer;

    fn file(text: &str) -> ProfilesFile {
        toml::from_str(text).expect("parses")
    }

    /// The places a jail never shows, as another product reads them: each
    /// dotdir that holds keys or mail, InnerWarden's own folder and the
    /// macOS mail, messages and browser folders, each under the home given,
    /// each once.
    ///
    /// FAILS ON REVERT: drop a name from one of the three lists and that
    /// place is missing here.
    #[test]
    fn the_places_a_jail_never_shows_are_named_under_the_home() {
        let home = std::path::Path::new("/home/dev");
        let places = jail_never_shows(home);
        let want: Vec<std::path::PathBuf> = [
            ".ssh",
            ".gnupg",
            ".aws",
            ".mozilla",
            ".thunderbird",
            ".config/innerwarden",
            "Library/Mail",
            "Library/Messages",
            "Library/Safari",
        ]
        .iter()
        .map(|name| home.join(name))
        .collect();
        assert_eq!(places, want);
        assert_eq!(
            home.join(JAIL_HIDDEN_CONFIG_DIR),
            home.join(".config").join("innerwarden")
        );
    }

    /// What a jail of each OS hides by name, as another product reads it: a
    /// Linux jail never binds any of the dotdirs; a macOS jail's sandbox
    /// denies `.ssh`, `.aws`, `.gnupg` and the three Library folders, and
    /// shows `~/.mozilla` and `~/.thunderbird`. Every place either names is
    /// in the list no project may overlap.
    ///
    /// FAILS ON REVERT: name `~/.mozilla` among what a macOS jail hides (the
    /// one list for both OSes, as before) and the macOS list holds it.
    #[test]
    fn what_a_jail_hides_is_named_for_each_os() {
        let home = std::path::Path::new("/home/dev");
        let names = |places: Vec<std::path::PathBuf>| -> Vec<String> {
            places
                .iter()
                .map(|place| {
                    place
                        .strip_prefix(home)
                        .unwrap()
                        .to_string_lossy()
                        .to_string()
                })
                .collect()
        };
        assert_eq!(
            names(jail_hides_on(home, false)),
            [
                ".ssh",
                ".gnupg",
                ".aws",
                ".mozilla",
                ".thunderbird",
                ".config/innerwarden"
            ]
        );
        assert_eq!(
            names(jail_hides_on(home, true)),
            [
                ".ssh",
                ".aws",
                ".gnupg",
                ".config/innerwarden",
                "Library/Mail",
                "Library/Messages",
                "Library/Safari"
            ]
        );
        let all = jail_never_shows(home);
        for macos in [false, true] {
            for place in jail_hides_on(home, macos) {
                assert!(all.contains(&place), "{place:?}");
            }
        }
    }

    fn profile(allow: &[&str], deny: &[&str]) -> AgentProfile {
        AgentProfile {
            allow_categories: allow.iter().map(|s| s.to_string()).collect(),
            deny_categories: deny.iter().map(|s| s.to_string()).collect(),
            ..AgentProfile::default()
        }
    }

    fn shell(general: Verdict, charged: &[&'static str], blocks_today: bool) -> ShellCall<'static> {
        let charged: &'static [&'static str] = Box::leak(charged.to_vec().into_boxed_slice());
        ShellCall {
            general,
            charged,
            blocks_today,
            names_llm_key: false,
            tainted: false,
        }
    }

    const ALL_TRUST: [Trust; 3] = [Trust::Declared, Trust::Observed, Trust::Confined];

    // -- the file ---------------------------------------------------------

    #[test]
    fn a_full_file_validates_into_sorted_lists() {
        let checked = validate(file(
            r#"
schema_version = 1
[profile.claude-code]
mode = "block-review"
allow_categories = ["tmp_execution", "bare_ip_fetch", "bare_ip_fetch"]
deny_categories = ["cloud_control_plane"]
mcp_tools_allow = ["read_file"]
mcp_tools_deny = ["delete_file"]
[profile.claude-code.jail]
project_rw = "/srv/app"
extra_ro = ["~/sdk", "/opt/tools"]
deny_read = ["config/prod.yaml"]
net = true
"#,
        ))
        .unwrap();
        let p = checked.get("claude-code").unwrap();
        assert_eq!(p.mode, Some(ProfileMode::BlockReview));
        assert_eq!(p.allow_categories, ["bare_ip_fetch", "tmp_execution"]);
        assert_eq!(p.deny_categories, ["cloud_control_plane"]);
        assert_eq!(p.mcp_tools_allow, ["read_file"]);
        assert_eq!(p.mcp_tools_deny, ["delete_file"]);
        assert_eq!(p.jail.project_rw.as_deref(), Some("/srv/app"));
        assert_eq!(p.jail.extra_ro, ["/opt/tools", "~/sdk"]);
        assert_eq!(p.jail.deny_read, ["config/prod.yaml"]);
        assert!(checked.get("cursor").is_none());
    }

    /// A name the engine never raises would be a rule that matches nothing.
    ///
    /// FAILS ON REVERT: accept any string as a category and this loads.
    #[test]
    fn an_unknown_category_is_an_error_that_names_it() {
        for field in ["allow_categories", "deny_categories"] {
            let err = validate(file(&format!(
                "schema_version = 1\n[profile.claude-code]\n{field} = [\"curl_to_bash\"]\n"
            )))
            .unwrap_err()
            .to_string();
            assert!(err.contains("`curl_to_bash` is not a signal name"), "{err}");
            assert!(err.contains(field), "{err}");
            assert!(
                err.contains("bare_ip_fetch"),
                "the valid names are listed: {err}"
            );
        }
        let err = validate(file(
            "schema_version = 1\n[profile.claude-code]\ndeny_categories = [\"atr:privilege-escalation\"]\n",
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("ATR category"), "{err}");
    }

    /// The floor is what the benchmark measures as blocked; an allow over it
    /// would let the score stay 100% while the cases fall to review.
    ///
    /// FAILS ON REVERT: drop the hard check at load and these load.
    #[test]
    fn an_allow_of_a_hard_signal_is_refused_at_load() {
        for hard in crate::mcp::AGENT_REVIEW_FLOOR.iter().chain(&[
            "guard_self_disable",
            "security_tooling_tamper",
            "sensitive_credential_read",
        ]) {
            let err = validate(file(&format!(
                "schema_version = 1\n[profile.claude-code]\nallow_categories = [\"{hard}\"]\n"
            )))
            .unwrap_err()
            .to_string();
            assert!(err.contains("is a hard rule"), "{hard}: {err}");
        }
        // Denying one is a tightening, and loads.
        assert!(validate(file(
            "schema_version = 1\n[profile.claude-code]\ndeny_categories = [\"download_and_execute\"]\n"
        ))
        .is_ok());
    }

    #[test]
    fn a_file_that_cannot_mean_one_thing_is_refused() {
        for (text, says) in [
            ("schema_version = 3\n", "unsupported schema_version 3"),
            ("schema_version = 0\n", "unsupported schema_version 0"),
            (
                "schema_version = 1\n[profile.Claude]\n",
                "is not an agent type",
            ),
            (
                "schema_version = 1\n[profile.claude-code]\nmode = \"monitor\"\n",
                "`monitor` is not a profile mode",
            ),
            (
                "schema_version = 1\n[profile.claude-code]\nmode = \"strict\"\n",
                "unknown mode `strict`",
            ),
            (
                "schema_version = 1\n[profile.claude-code]\nallow_categories = [\"tmp_execution\"]\ndeny_categories = [\"tmp_execution\"]\n",
                "both allowed and denied",
            ),
            (
                "schema_version = 1\n[profile.claude-code]\nmcp_tools_allow = [\"x\"]\nmcp_tools_deny = [\"x\"]\n",
                "both allowed and denied",
            ),
            (
                "schema_version = 1\n[profile.claude-code]\nmcp_tools_deny = [\"two words\"]\n",
                "is not a tool name",
            ),
            (
                "schema_version = 1\n[profile.claude-code.jail]\nnet = false\n",
                "`net = false` is not available",
            ),
            (
                "schema_version = 1\n[profile.claude-code.jail]\nproject_rw = \"relative/dir\"\n",
                "jail.project_rw",
            ),
            (
                "schema_version = 1\n[profile.claude-code.jail]\nextra_ro = [\"/opt/../etc\"]\n",
                "jail.extra_ro",
            ),
            (
                "schema_version = 1\n[profile.claude-code.jail]\ndeny_read = [\"/etc/passwd\"]\n",
                "jail.deny_read",
            ),
            (
                "schema_version = 1\n[profile.claude-code.jail]\ndeny_read = [\"../other/.env\"]\n",
                "jail.deny_read",
            ),
        ] {
            let err = validate(file(text)).unwrap_err().to_string();
            assert!(err.contains(says), "{text}: {err}");
        }
    }

    /// An unknown key is a typo of a known one, not a key to ignore.
    #[test]
    fn an_unknown_key_does_not_parse() {
        for text in [
            "schema_version = 1\n[profile.claude-code]\ndeny_category = [\"tmp_execution\"]\n",
            "schema_version = 1\nprofiles = {}\n",
            "schema_version = 1\n[profile.claude-code.jail]\nextra_rw = [\"/x\"]\n",
        ] {
            let err = parse(text.as_bytes()).unwrap_err().to_string();
            assert!(err.contains("not a profiles file"), "{text}: {err}");
        }
    }

    #[test]
    fn two_files_merge_without_losing_a_denial() {
        let system = validate(file(
            "schema_version = 1\n[profile.claude-code]\nmode = \"enforce\"\nallow_categories = [\"tmp_execution\", \"bare_ip_fetch\"]\n[profile.claude-code.jail]\nproject_rw = \"/srv/a\"\ndeny_read = [\"a\"]\n",
        ))
        .unwrap();
        let user = validate(file(
            "schema_version = 1\n[profile.claude-code]\nmode = \"block-review\"\ndeny_categories = [\"tmp_execution\"]\n[profile.claude-code.jail]\nproject_rw = \"~/b\"\ndeny_read = [\"b\"]\n[profile.cursor]\n",
        ))
        .unwrap();
        assert_eq!(check_user_file(&user), Ok(()));
        let merged = merge(Some(&system), Some(&user));
        let p = merged.get("claude-code").unwrap();
        assert_eq!(p.mode, Some(ProfileMode::BlockReview), "the stricter mode");
        assert_eq!(p.deny_categories, ["tmp_execution"]);
        assert_eq!(p.allow_categories, ["bare_ip_fetch", "tmp_execution"]);
        assert_eq!(p.jail.project_rw.as_deref(), Some("~/b"));
        assert_eq!(p.jail.deny_read, ["a", "b"]);
        assert!(merged.get("cursor").is_some());
        // Allowed in one file and denied in the other: denied.
        assert_eq!(command_rule(p, &["tmp_execution"]), Some(LayerRule::Deny));
        assert_eq!(merge(None, None), AgentProfiles::default());
    }

    /// A file the agent's own account can write must not be able to loosen
    /// anything: inside the jail the user's directory is the jail's.
    ///
    /// FAILS ON REVERT: make `check_user_file` return `Ok(())` and these
    /// load.
    #[test]
    fn the_users_file_can_tighten_but_never_relax() {
        for (text, field) in [
            ("allow_categories = [\"bare_ip_fetch\"]", "allow_categories"),
            ("mcp_tools_allow = [\"read_file\"]", "mcp_tools_allow"),
            ("mode = \"enforce\"", "mode"),
        ] {
            let user = validate(file(&format!(
                "schema_version = 1\n[profile.claude-code]\n{text}\n"
            )))
            .unwrap();
            let err = check_user_file(&user).unwrap_err().to_string();
            assert!(
                err.contains(field) && err.contains("only /etc/innerwarden"),
                "{err}"
            );
        }
        let tightening = validate(file(
            "schema_version = 1\n[profile.claude-code]\nmode = \"block-review\"\ndeny_categories = [\"bare_ip_fetch\"]\nmcp_tools_deny = [\"x\"]\n[profile.claude-code.jail]\nextra_ro = [\"/opt\"]\n",
        ))
        .unwrap();
        assert_eq!(check_user_file(&tightening), Ok(()));
    }

    // -- schema 2: when the hook asks the host ------------------------------

    const EVERY: &str = "schema_version = 2\n[profile.claude-code]\nask_host = \"every_command\"\n";

    #[test]
    fn a_schema_2_file_is_read_with_ask_host() {
        let checked = parse(EVERY.as_bytes()).unwrap();
        assert_eq!(
            checked.get("claude-code").unwrap().ask_host,
            Some(AskHost::EveryCommand)
        );
        let merged = merge(Some(&checked), None);
        assert_eq!(merged.ask_host(Some("claude-code")), AskHost::EveryCommand);
        assert_eq!(merged.ask_host(Some("cursor")), AskHost::Review);
        assert_eq!(merged.ask_host(None), AskHost::Review);
        let review = parse(
            b"schema_version = 2\n[profile.claude-code]\nask_host = \"review\"\n[profile.cursor]\n",
        )
        .unwrap();
        let review = merge(Some(&review), None);
        assert_eq!(review.ask_host(Some("claude-code")), AskHost::Review);
        assert_eq!(review.ask_host(Some("cursor")), AskHost::Review);
        // A type assigned to a named profile gets that profile's ask_host;
        // one assigned the general rules gets the default.
        let assigned = merge(
            Some(
                &parse(
                    b"schema_version = 2\n[profile.kernel]\nask_host = \"every_command\"\n\
                      [agent.claude-code]\nprofile = \"kernel\"\n[agent.codex]\nprofile = \"general\"\n",
                )
                .unwrap(),
            ),
            None,
        );
        assert_eq!(
            assigned.ask_host(Some("claude-code")),
            AskHost::EveryCommand
        );
        assert_eq!(assigned.ask_host(Some("codex")), AskHost::Review);
        // Without the key, a file of schema 2 reads as the same file of
        // schema 1.
        let body =
            "[profile.claude-code]\nmode = \"enforce\"\nallow_categories = [\"bare_ip_fetch\"]\n";
        assert_eq!(
            parse(format!("schema_version = 2\n{body}").as_bytes()).unwrap(),
            parse(format!("schema_version = 1\n{body}").as_bytes()).unwrap()
        );
    }

    /// A build that reads only schema 1 refuses a file of schema 2 whole, so
    /// the key must never be read in a file that claims schema 1: there an
    /// older build and this one would read the same file two ways.
    ///
    /// FAILS ON REVERT: drop the schema check from `validate_ask_host` and the
    /// first case loads.
    #[test]
    fn ask_host_in_a_schema_1_file_is_refused() {
        for (text, says) in [
            (
                "schema_version = 1\n[profile.claude-code]\nask_host = \"every_command\"\n",
                "needs schema_version = 2",
            ),
            (
                "schema_version = 1\n[profile.claude-code]\nask_host = \"review\"\n",
                "needs schema_version = 2",
            ),
            (
                "schema_version = 2\n[profile.claude-code]\nask_host = \"always\"\n",
                "unknown value `always`",
            ),
            (
                "schema_version = 2\n[profile.claude-code]\nask_host = \"Every_Command\"\n",
                "unknown value",
            ),
        ] {
            let err = parse(text.as_bytes()).unwrap_err().to_string();
            assert!(err.contains(says), "{text}: {err}");
            assert!(err.contains("ask_host"), "{text}: {err}");
        }
    }

    /// Inside the jail the user's file is one the agent can write, and the
    /// host deciding every command is the system file's to ask for.
    ///
    /// FAILS ON REVERT: drop the `ask_host` check from `check_user_file` and
    /// both values load in the user's file.
    #[test]
    fn the_users_file_never_says_when_the_hook_asks() {
        for value in ["every_command", "review"] {
            let user = parse(
                format!("schema_version = 2\n[profile.claude-code]\nask_host = \"{value}\"\n")
                    .as_bytes(),
            )
            .unwrap();
            let err = check_user_file(&user).unwrap_err().to_string();
            assert!(
                err.contains("ask_host") && err.contains("only /etc/innerwarden"),
                "{value}: {err}"
            );
        }
        let tightening = parse(
            b"schema_version = 2\n[profile.claude-code]\ndeny_categories = [\"bare_ip_fetch\"]\n",
        )
        .unwrap();
        assert_eq!(check_user_file(&tightening), Ok(()));
    }

    /// Even handed a user's side that says it (the reader refuses one), the
    /// merge takes `ask_host` from the system file alone.
    ///
    /// FAILS ON REVERT: take `ask_host` from either side in `merge` and the
    /// user's `every_command` stands.
    #[test]
    fn merge_takes_ask_host_from_the_system_file_only() {
        let system = parse(b"schema_version = 2\n[profile.claude-code]\n").unwrap();
        let user = parse(EVERY.as_bytes()).unwrap();
        let merged = merge(Some(&system), Some(&user));
        assert_eq!(merged.get("claude-code").unwrap().ask_host, None);
        assert_eq!(merged.ask_host(Some("claude-code")), AskHost::Review);
        assert_eq!(
            merge(None, Some(&user)).ask_host(Some("claude-code")),
            AskHost::Review
        );
        let review =
            parse(b"schema_version = 2\n[profile.claude-code]\nask_host = \"review\"\n").unwrap();
        let both = merge(Some(&user), Some(&review));
        assert_eq!(both.ask_host(Some("claude-code")), AskHost::EveryCommand);
    }

    /// Profiles from a file of schema 1 serialise exactly as before the key
    /// existed: no `ask_host`, the same bytes, and a copy saved before reads
    /// back.
    #[test]
    fn a_schema_1_file_serialises_and_reads_as_before() {
        let merged = merge(
            Some(
                &parse(
                    b"schema_version = 1\n[profile.claude-code]\nmode = \"enforce\"\nallow_categories = [\"bare_ip_fetch\"]\n",
                )
                .unwrap(),
            ),
            None,
        );
        let golden = r#"{"types":{"claude-code":{"mode":"enforce","allow_categories":["bare_ip_fetch"],"deny_categories":[],"mcp_tools_allow":[],"mcp_tools_deny":[],"jail":{"project_rw":null,"extra_ro":[],"deny_read":[]},"source":"system"}}}"#;
        assert_eq!(serde_json::to_string(&merged).unwrap(), golden);
        let read: AgentProfiles = serde_json::from_str(golden).unwrap();
        assert_eq!(read, merged);
        assert_eq!(read.ask_host(Some("claude-code")), AskHost::Review);
        let every = merge(Some(&parse(EVERY.as_bytes()).unwrap()), None);
        let text = serde_json::to_string(&every).unwrap();
        assert!(text.contains(r#""ask_host":"every_command""#), "{text}");
        assert_eq!(serde_json::from_str::<AgentProfiles>(&text).unwrap(), every);
    }

    #[test]
    fn asking_about_every_command_is_said_changed_and_a_relaxation() {
        let plain = merge(
            Some(&parse(b"schema_version = 1\n[profile.claude-code]\n").unwrap()),
            None,
        );
        let every = merge(Some(&parse(EVERY.as_bytes()).unwrap()), None);
        let (before, after) = (plain.get("claude-code"), every.get("claude-code"));
        assert!(relaxes(before, after));
        assert!(!relaxes(after, before), "asking less is not a relaxation");
        assert!(relaxes(None, after));
        assert!(!relaxes(after, after));
        assert_eq!(
            changes(&plain, &every),
            [ProfileChange::to_type(
                "ask_host_changed",
                "claude-code",
                "every_command"
            )]
        );
        assert_eq!(
            changes(&every, &plain),
            [ProfileChange::to_type(
                "ask_host_changed",
                "claude-code",
                ""
            )]
        );
        assert_eq!(
            describe(after),
            [
                "In a jail, Active Defence on this host is asked about every shell command, \
                 not only a review."
            ]
        );
        assert_eq!(describe(before), ["Your general rules, nothing added."]);
    }

    /// A verb that edits a file of schema 2 keeps its schema and its key; a
    /// file the verbs create is of schema 1, as before.
    #[test]
    fn an_edit_keeps_the_schema_it_found() {
        let stamp = Stamp {
            by: "maria",
            at: "2026-10-18T09:00:00Z",
        };
        let edited = edit_approve(EVERY, "claude-code", None, None, stamp).unwrap();
        let read = parse(edited.as_bytes()).unwrap();
        assert_eq!(
            read.get("claude-code").unwrap().ask_host,
            Some(AskHost::EveryCommand)
        );
        assert!(edited.starts_with("schema_version = 2\n"), "{edited}");
        let fresh = edit_approve("", "claude-code", None, None, stamp).unwrap();
        assert!(fresh.starts_with("schema_version = 1\n"), "{fresh}");
    }

    // -- when the jail starts, and what of the home it hides ---------------

    const STRICT: &str = "schema_version = 2\n[profile.claude-code.jail]\n\
        start = \"only_when_admitted\"\nhide_home = [\".cache/git/credential\"]\n";

    #[test]
    fn a_schema_2_jail_says_when_it_starts_and_what_it_hides() {
        let read = parse(STRICT.as_bytes()).unwrap();
        let jail = &read.get("claude-code").unwrap().jail;
        assert_eq!(jail.start, Some(JailStart::OnlyWhenAdmitted));
        assert_eq!(jail.start(), JailStart::OnlyWhenAdmitted);
        assert_eq!(jail.hide_home, [".cache/git/credential"]);
        let always =
            parse(b"schema_version = 2\n[profile.claude-code.jail]\nstart = \"always\"\n").unwrap();
        assert_eq!(
            always.get("claude-code").unwrap().jail.start(),
            JailStart::Always
        );
        // No `start`: the jail starts as it always did.
        let plain = parse(b"schema_version = 2\n[profile.claude-code.jail]\n").unwrap();
        assert_eq!(plain.get("claude-code").unwrap().jail.start, None);
        assert_eq!(
            plain.get("claude-code").unwrap().jail.start(),
            JailStart::Always
        );
        assert!(JailStart::OnlyWhenAdmitted > JailStart::Always);
    }

    /// Both keys are schema 2's: a build that reads only schema 1 refuses
    /// the whole file, so neither is ever quietly dropped.
    ///
    /// FAILS ON REVERT: drop the schema check from `validate_jail_start` or
    /// from `validate_hide_home` and its line parses.
    #[test]
    fn start_and_hide_home_in_a_schema_1_file_are_refused() {
        for (text, key) in [
            (
                "schema_version = 1\n[profile.claude-code.jail]\nstart = \"only_when_admitted\"\n",
                "jail.start",
            ),
            (
                "schema_version = 1\n[profile.claude-code.jail]\nstart = \"always\"\n",
                "jail.start",
            ),
            (
                "schema_version = 1\n[profile.claude-code.jail]\nhide_home = [\".cache/git/credential\"]\n",
                "jail.hide_home",
            ),
            (
                "schema_version = 2\n[profile.claude-code.jail]\nstart = \"when_admitted\"\n",
                "jail.start",
            ),
            (
                "schema_version = 2\n[profile.claude-code.jail]\nstart = \"Only_When_Admitted\"\n",
                "jail.start",
            ),
        ] {
            let err = parse(text.as_bytes()).unwrap_err().to_string();
            assert!(err.contains(key), "{text}: {err}");
        }
    }

    /// A hidden home path is a path under the home: written relative to it,
    /// with no step that leaves it or names nothing, no glob, and bounded.
    ///
    /// FAILS ON REVERT: accept any string in `is_home_path` and each line
    /// here parses.
    #[test]
    fn a_hidden_home_path_stays_under_the_home() {
        for bad in [
            "",
            "/etc/shadow",
            "~/.ssh",
            "..",
            "../other",
            ".cache/../../etc",
            "./.cache",
            ".cache//git",
            ".cache/",
            ".cache/*",
            ".cache/git?",
            ".cache/[ab]",
            ".cache/\u{7}bell",
        ] {
            let text = format!(
                "schema_version = 2\n[profile.claude-code.jail]\nhide_home = [{}]\n",
                toml_edit::Value::from(bad)
            );
            let err = parse(text.as_bytes()).unwrap_err().to_string();
            assert!(err.contains("jail.hide_home"), "{bad:?}: {err}");
        }
        let long = "a".repeat(256);
        let text =
            format!("schema_version = 2\n[profile.claude-code.jail]\nhide_home = [\"{long}\"]\n");
        assert!(parse(text.as_bytes()).is_err());
        let many: Vec<String> = (0..=MAX_HIDE_HOME).map(|i| format!("\"d{i}\"")).collect();
        let text = format!(
            "schema_version = 2\n[profile.claude-code.jail]\nhide_home = [{}]\n",
            many.join(",")
        );
        assert!(parse(text.as_bytes()).is_err());
        for good in [".cache/git/credential", "notes", ".config/some tool/state"] {
            let text = format!(
                "schema_version = 2\n[profile.claude-code.jail]\nhide_home = [{}]\n",
                toml_edit::Value::from(good)
            );
            assert!(parse(text.as_bytes()).is_ok(), "{good:?}");
        }
    }

    /// The user's file may say when the jail starts and what it hides, and
    /// can only tighten both: merged, the stricter `start` and every hidden
    /// path of both files hold.
    ///
    /// FAILS ON REVERT: take the user's `start` as it is in `merge` (or drop
    /// the union of `hide_home`) and the user's `always` opens a jail the
    /// system file starts only when admitted (or a system path is shown).
    #[test]
    fn the_users_file_only_tightens_when_the_jail_starts_and_what_it_hides() {
        let system = checked(STRICT);
        let user = checked(
            "schema_version = 2\n[profile.claude-code.jail]\nstart = \"always\"\n\
             hide_home = [\".local/share/keyrings\"]\n",
        );
        assert_eq!(check_user_file(&user), Ok(()));
        let merged = merge(Some(&system), Some(&user));
        let jail = &merged.get("claude-code").unwrap().jail;
        assert_eq!(jail.start(), JailStart::OnlyWhenAdmitted);
        assert_eq!(
            jail.hide_home,
            [".cache/git/credential", ".local/share/keyrings"]
        );
        let tightening = checked(
            "schema_version = 2\n[profile.claude-code.jail]\nstart = \"only_when_admitted\"\n",
        );
        assert_eq!(check_user_file(&tightening), Ok(()));
        let open = checked("schema_version = 1\n[profile.claude-code]\n");
        let merged = merge(Some(&open), Some(&tightening));
        assert_eq!(
            merged.get("claude-code").unwrap().jail.start(),
            JailStart::OnlyWhenAdmitted
        );
        assert_eq!(
            merge(Some(&tightening), None)
                .get("claude-code")
                .unwrap()
                .jail
                .start(),
            JailStart::OnlyWhenAdmitted
        );
    }

    /// Starting without the host's admission, and showing a hidden home
    /// path again, are relaxations; the other way is not. Each change is
    /// said, and the profile says both in words.
    ///
    /// FAILS ON REVERT: drop either line from `relaxes` and its case is not
    /// a relaxation.
    #[test]
    fn starting_without_admission_or_showing_a_hidden_path_is_a_relaxation() {
        let strict = merge(Some(&checked(STRICT)), None);
        let plain = merge(
            Some(&checked("schema_version = 2\n[profile.claude-code.jail]\n")),
            None,
        );
        let (strict_p, plain_p) = (strict.get("claude-code"), plain.get("claude-code"));
        assert!(relaxes(strict_p, plain_p));
        assert!(
            !relaxes(plain_p, strict_p),
            "starting only when admitted tightens"
        );
        let only_start = merge(
            Some(&checked(
                "schema_version = 2\n[profile.claude-code.jail]\nstart = \"only_when_admitted\"\n",
            )),
            None,
        );
        assert!(relaxes(only_start.get("claude-code"), plain_p));
        assert!(
            relaxes(strict_p, only_start.get("claude-code")),
            "a path shown again"
        );
        assert_eq!(
            changes(&plain, &strict),
            [
                ProfileChange::to_type("jail_start_changed", "claude-code", "only_when_admitted"),
                ProfileChange::to_type(
                    "jail_hide_home_added",
                    "claude-code",
                    ".cache/git/credential"
                ),
            ]
        );
        assert_eq!(
            changes(&strict, &plain),
            [
                ProfileChange::to_type("jail_start_changed", "claude-code", ""),
                ProfileChange::to_type(
                    "jail_hide_home_removed",
                    "claude-code",
                    ".cache/git/credential"
                ),
            ]
        );
        assert_eq!(
            describe(strict_p),
            [
                "Hidden from the home in the jail: .cache/git/credential.",
                "The jail starts only when Active Defence on this host admits it.",
            ]
        );
    }

    /// A file of schema 1 serialises as before the two keys existed, and
    /// one of schema 2 that says them reads back.
    #[test]
    fn a_jail_without_the_new_keys_serialises_as_before() {
        let merged = merge(Some(&checked(STRICT)), None);
        let text = serde_json::to_string(&merged).unwrap();
        assert!(
            text.contains(r#""start":"only_when_admitted","hide_home":[".cache/git/credential"]"#),
            "{text}"
        );
        assert_eq!(
            serde_json::from_str::<AgentProfiles>(&text).unwrap(),
            merged
        );
        let plain = merge(
            Some(&checked("schema_version = 1\n[profile.claude-code]\n")),
            None,
        );
        let text = serde_json::to_string(&plain).unwrap();
        assert!(
            !text.contains("start") && !text.contains("hide_home"),
            "{text}"
        );
    }

    /// The host writes the jail's settings through the same editors the
    /// verbs use: in place, keeping the rest of the file, raised to schema 2
    /// where a key needs it, and read back by `parse`.
    #[test]
    fn the_jail_editors_write_what_parse_reads_and_keep_the_rest() {
        let text = "# kept\nschema_version = 1\n\n[profile.claude-code]\n\
                    deny_categories = [\"bare_ip_fetch\"] # kept too\n";
        let started = set_jail_start(text, "claude-code", JailStart::OnlyWhenAdmitted).unwrap();
        assert!(started.contains("# kept\n"), "{started}");
        assert!(started.contains("# kept too"), "{started}");
        assert!(started.contains("schema_version = 2"), "{started}");
        let read = parse(started.as_bytes()).unwrap();
        let profile = read.get("claude-code").unwrap();
        assert_eq!(profile.jail.start(), JailStart::OnlyWhenAdmitted);
        assert_eq!(profile.deny_categories, ["bare_ip_fetch"]);
        let versions = runtime_versions_dir("claude-code").unwrap();
        assert_eq!(versions, "~/.local/share/claude/versions");
        assert_eq!(runtime_versions_dir("cursor"), None);
        let with_ro =
            set_jail_path(&started, "claude-code", JailList::ExtraRo, versions, true).unwrap();
        let hidden = set_jail_path(
            &with_ro,
            "claude-code",
            JailList::HideHome,
            ".cache/git/credential",
            true,
        )
        .unwrap();
        let again = set_jail_path(
            &hidden,
            "claude-code",
            JailList::HideHome,
            ".cache/git/credential",
            true,
        )
        .unwrap();
        assert_eq!(again, hidden, "adding twice adds once");
        let jail = parse(hidden.as_bytes())
            .unwrap()
            .get("claude-code")
            .unwrap()
            .jail
            .clone();
        assert_eq!(jail.extra_ro, [versions]);
        assert_eq!(jail.hide_home, [".cache/git/credential"]);
        let shown = set_jail_path(
            &hidden,
            "claude-code",
            JailList::HideHome,
            ".cache/git/credential",
            false,
        )
        .unwrap();
        let back = set_jail_start(&shown, "claude-code", JailStart::Always).unwrap();
        let jail = parse(back.as_bytes())
            .unwrap()
            .get("claude-code")
            .unwrap()
            .jail
            .clone();
        assert!(jail.hide_home.is_empty());
        assert_eq!(jail.start, Some(JailStart::Always));
        // A new file is made of schema 2 for a key of schema 2.
        let fresh = set_jail_start("", "cursor", JailStart::OnlyWhenAdmitted).unwrap();
        assert!(fresh.starts_with("schema_version = 2\n"), "{fresh}");
        assert!(parse(fresh.as_bytes()).is_ok(), "{fresh}");
        // An extra read-only path keeps the schema it found.
        let ro_only = set_jail_path(
            "schema_version = 1\n",
            "claude-code",
            JailList::ExtraRo,
            versions,
            true,
        )
        .unwrap();
        assert!(ro_only.starts_with("schema_version = 1\n"), "{ro_only}");
    }

    /// An editor refuses what the file could not hold, and a type whose
    /// rules come from another profile: its own table would change nothing.
    #[test]
    fn the_jail_editors_refuse_what_would_not_apply() {
        for (list, path) in [
            (JailList::HideHome, "/etc/shadow"),
            (JailList::HideHome, "../x"),
            (JailList::ExtraRo, "relative/path"),
            (JailList::ExtraRo, "/opt/../etc"),
        ] {
            assert!(
                set_jail_path("", "claude-code", list, path, true).is_err(),
                "{list:?} {path}"
            );
        }
        assert!(set_jail_start("", "Not An Id", JailStart::Always).is_err());
        for assigned in ["engineering", GENERAL_PROFILE] {
            let text = format!(
                "schema_version = 1\n[profile.engineering]\n[agent.claude-code]\nprofile = \"{assigned}\"\n"
            );
            let err = set_jail_start(&text, "claude-code", JailStart::OnlyWhenAdmitted)
                .unwrap_err()
                .to_string();
            assert!(err.contains(assigned), "{err}");
        }
    }

    // -- the decisions ----------------------------------------------------

    /// "An agent declared as the permissive type gets the general policy."
    ///
    /// FAILS ON REVERT: relax for `Observed` too in `identity::decide` and the
    /// observed row turns `allow`.
    #[test]
    fn a_declared_or_observed_agent_of_a_permissive_type_gets_the_general_policy() {
        let permissive = profile(&["bare_ip_fetch", "tmp_execution"], &[]);
        let call = shell(Verdict::Review, &["bare_ip_fetch", "tmp_execution"], true);
        for trust in [Trust::Declared, Trust::Observed] {
            let out = decide_shell(&call, Some(("claude-code", &permissive)), true, trust);
            assert_eq!(out.decision.verdict, Verdict::Review, "{trust:?}");
            assert_eq!(out.decision.deciding_layer, RuleLayer::General);
            assert!(out.blocks, "the line blocks reviews: {trust:?}");
            assert_eq!(out.note, None);
        }
    }

    /// The relaxation a profile would have made is reported as withheld only
    /// for an instance that does not run confined, only when the general
    /// rules decided, and never when nothing would have allowed it.
    ///
    /// FAILS ON REVERT: drop the trust and deciding-layer check from
    /// `relaxation_withheld` (report what the profile would allow, whatever
    /// decided) and the confined row reports a withheld relaxation.
    #[test]
    fn a_relaxation_is_withheld_only_from_an_instance_that_is_not_confined() {
        let permissive = profile(&["bare_ip_fetch", "tmp_execution"], &[]);
        let review = shell(Verdict::Review, &["bare_ip_fetch", "tmp_execution"], true);
        for trust in [Trust::Declared, Trust::Observed] {
            let out = decide_shell(&review, Some(("claude-code", &permissive)), true, trust);
            assert!(out.relaxation_withheld, "{trust:?}");
        }
        let confined = decide_shell(
            &review,
            Some(("claude-code", &permissive)),
            true,
            Trust::Confined,
        );
        assert!(!confined.relaxation_withheld);
        // A general deny is never relaxed, so nothing was withheld.
        let deny = shell(Verdict::Deny, &["bare_ip_fetch"], true);
        let out = decide_shell(
            &deny,
            Some(("claude-code", &permissive)),
            true,
            Trust::Observed,
        );
        assert!(!out.relaxation_withheld);
        // No profile, or one that allows nothing charged: nothing withheld.
        let out = decide_shell(&review, None, true, Trust::Observed);
        assert!(!out.relaxation_withheld);
        let narrow = profile(&["bare_ip_fetch"], &[]);
        let out = decide_shell(
            &review,
            Some(("claude-code", &narrow)),
            true,
            Trust::Observed,
        );
        assert!(!out.relaxation_withheld);
    }

    #[test]
    fn a_confined_instance_of_the_type_gets_the_profile() {
        let permissive = profile(&["bare_ip_fetch", "tmp_execution"], &[]);
        let call = shell(Verdict::Review, &["bare_ip_fetch", "tmp_execution"], true);
        let out = decide_shell(
            &call,
            Some(("claude-code", &permissive)),
            true,
            Trust::Confined,
        );
        assert_eq!(out.decision.verdict, Verdict::Allow);
        assert_eq!(out.decision.deciding_layer, RuleLayer::AgentType);
        assert!(!out.blocks);
        assert!(out
            .note
            .unwrap()
            .contains("allows bare_ip_fetch, tmp_execution"));
    }

    /// One signal the profile does not name and the review stands.
    #[test]
    fn an_allow_needs_every_charged_signal_listed() {
        let partial = profile(&["bare_ip_fetch"], &[]);
        for charged in [
            &["bare_ip_fetch", "tmp_execution"][..],
            &["bare_ip_fetch", "atr:privilege-escalation"][..],
            &["bare_ip_fetch", "fetch_exec_no_tls"][..],
            &[][..],
        ] {
            assert_eq!(command_rule(&partial, charged), None, "{charged:?}");
        }
        assert_eq!(
            command_rule(&partial, &["bare_ip_fetch"]),
            Some(LayerRule::Allow)
        );
    }

    #[test]
    fn an_argument_from_a_tool_result_is_never_relaxed() {
        let permissive = profile(&["bare_ip_fetch"], &[]);
        let mut call = shell(Verdict::Review, &["bare_ip_fetch"], true);
        call.tainted = true;
        let out = decide_shell(
            &call,
            Some(("claude-code", &permissive)),
            true,
            Trust::Confined,
        );
        assert_eq!(out.decision.verdict, Verdict::Review);
        assert!(out.blocks);
    }

    /// A general refusal is not lifted by a profile, even for a confined
    /// instance: a profile relaxes a review.
    ///
    /// FAILS ON REVERT: check the allow before the general deny in
    /// `identity::decide` and this sees `allow`.
    #[test]
    fn a_general_deny_beats_a_profile_allow() {
        let permissive = profile(&["dangerous_command"], &[]);
        let call = shell(Verdict::Deny, &["dangerous_command"], true);
        for trust in ALL_TRUST {
            let out = decide_shell(&call, Some(("claude-code", &permissive)), false, trust);
            assert_eq!(
                (out.decision.verdict, out.decision.deciding_layer),
                (Verdict::Deny, RuleLayer::General),
                "{trust:?}"
            );
            assert!(out.blocks);
        }
    }

    #[test]
    fn a_profile_deny_holds_at_every_trust() {
        let strict = profile(&[], &["bare_ip_fetch"]);
        let call = shell(Verdict::Review, &["bare_ip_fetch"], false);
        for trust in ALL_TRUST {
            let out = decide_shell(&call, Some(("claude-code", &strict)), false, trust);
            assert_eq!(
                (out.decision.verdict, out.decision.deciding_layer),
                (Verdict::Deny, RuleLayer::AgentType)
            );
            assert!(out.blocks);
            assert!(out
                .note
                .as_deref()
                .unwrap()
                .contains("denies bare_ip_fetch"));
        }
        // An allow-class command carrying a denied signal is refused too.
        let low = shell(Verdict::Allow, &["bare_ip_fetch"], false);
        assert!(decide_shell(&low, Some(("x", &strict)), false, Trust::Declared).blocks);
    }

    /// A hard signal the general layer blocks is the hard layer's, whatever
    /// the profile says and at every trust; the LLM key is refused even where
    /// the engine saw nothing.
    ///
    /// FAILS ON REVERT: leave `hard_refused` false and the LLM-key row is
    /// `allow`.
    #[test]
    fn a_hard_rule_beats_everything() {
        // A profile cannot list a floor signal, so the strongest it can do is
        // allow every other one the command carries.
        let permissive = profile(&["tmp_execution"], &[]);
        let floor = shell(
            Verdict::Review,
            &["download_and_execute", "tmp_execution"],
            true,
        );
        let mut key = shell(Verdict::Allow, &[], false);
        key.names_llm_key = true;
        for trust in ALL_TRUST {
            for line_block_review in [false, true] {
                for call in [&floor, &key] {
                    let out = decide_shell(
                        call,
                        Some(("claude-code", &permissive)),
                        line_block_review,
                        trust,
                    );
                    assert_eq!(
                        (out.decision.verdict, out.decision.deciding_layer),
                        (Verdict::Deny, RuleLayer::Hard),
                        "{trust:?} {call:?}"
                    );
                    assert!(out.blocks);
                }
            }
        }
        let out = decide_shell(&key, None, false, Trust::Declared);
        assert!(out.note.unwrap().contains("LLM key"));
    }

    /// With no profile for the type and nothing hard, the outcome is the
    /// general layer's exactly: what the hook did before profiles.
    #[test]
    fn without_a_profile_the_outcome_is_the_hooks_own() {
        for general in [Verdict::Allow, Verdict::Review, Verdict::Deny] {
            for line_block_review in [false, true] {
                for floor in [false, true] {
                    let charged: &[&str] = if floor {
                        &["download_and_execute"]
                    } else {
                        &["bare_ip_fetch"]
                    };
                    let blocks_today = general == Verdict::Deny
                        || (general == Verdict::Review && (line_block_review || floor));
                    let call = ShellCall {
                        general,
                        charged,
                        blocks_today,
                        names_llm_key: false,
                        tainted: false,
                    };
                    for trust in ALL_TRUST {
                        let out = decide_shell(&call, None, line_block_review, trust);
                        assert_eq!(
                            out.blocks, blocks_today,
                            "{general:?} {line_block_review} {floor} {trust:?}"
                        );
                        assert_eq!(out.note, None);
                    }
                }
            }
        }
    }

    /// `enforce` lets a review run on a line that blocks reviews: confined
    /// only. `block-review` holds one to block at any trust.
    ///
    /// FAILS ON REVERT: relax the mode for `Observed` too in `review_blocks`
    /// and the observed row lets the review run.
    #[test]
    fn a_profile_mode_relaxes_for_a_confined_instance_and_tightens_for_all() {
        let mut relaxed = profile(&[], &[]);
        relaxed.mode = Some(ProfileMode::Enforce);
        let mut strict = profile(&[], &[]);
        strict.mode = Some(ProfileMode::BlockReview);
        let review = shell(Verdict::Review, &["bare_ip_fetch"], true);
        assert!(!decide_shell(&review, Some(("x", &relaxed)), true, Trust::Confined).blocks);
        for trust in [Trust::Declared, Trust::Observed] {
            assert!(
                decide_shell(&review, Some(("x", &relaxed)), true, trust).blocks,
                "{trust:?}"
            );
        }
        let quiet = shell(Verdict::Review, &["bare_ip_fetch"], false);
        for trust in ALL_TRUST {
            let out = decide_shell(&quiet, Some(("x", &strict)), false, trust);
            assert!(out.blocks, "{trust:?}");
            assert!(out.note.unwrap().contains("holds a review to block"));
        }
        // A floor review stays blocked under a relaxed mode: it is hard.
        let floor = shell(Verdict::Review, &["download_and_execute"], true);
        assert!(decide_shell(&floor, Some(("x", &relaxed)), false, Trust::Confined).blocks);
    }

    #[test]
    fn a_tool_rule_matches_names_exactly() {
        let mut p = profile(&[], &[]);
        p.mcp_tools_deny = vec!["delete_file".into()];
        p.mcp_tools_allow = vec!["read_file".into()];
        assert_eq!(tool_rule(&p, "delete_file", &[]), Some(LayerRule::Deny));
        assert_eq!(tool_rule(&p, "Delete_File", &[]), None);
        assert_eq!(tool_rule(&p, "read_file", &[]), Some(LayerRule::Allow));
        assert_eq!(tool_rule(&p, "read_file", &["tmp_execution"]), None);
        p.deny_categories = vec!["tmp_execution".into()];
        assert_eq!(
            tool_rule(&p, "bash", &["tmp_execution"]),
            Some(LayerRule::Deny)
        );
    }

    #[test]
    fn in_the_proxy_a_profile_denies_but_never_lifts_a_refusal() {
        let mut p = profile(&[], &[]);
        p.mcp_tools_deny = vec!["delete_file".into()];
        p.mcp_tools_allow = vec!["save".into()];
        let call = |tool, allowed| ToolCallFacts {
            tool,
            allowed,
            has_alerts: !allowed,
            charged: &[],
            hard_alert: false,
            names_llm_key: false,
        };
        for trust in ALL_TRUST {
            let (d, note) = decide_tool_call(&call("delete_file", true), Some(("x", &p)), trust);
            assert_eq!(
                (d.verdict, d.deciding_layer),
                (Verdict::Deny, RuleLayer::AgentType)
            );
            assert!(note.unwrap().contains("`delete_file`"));
            let (d, _) = decide_tool_call(&call("save", false), Some(("x", &p)), trust);
            assert_eq!(
                (d.verdict, d.deciding_layer),
                (Verdict::Deny, RuleLayer::General)
            );
        }
        let (d, _) = decide_tool_call(&call("weather", true), None, Trust::Declared);
        assert_eq!(
            (d.verdict, d.deciding_layer),
            (Verdict::Allow, RuleLayer::General)
        );
        let mut key = call("read_file", true);
        key.names_llm_key = true;
        let (d, note) = decide_tool_call(&key, Some(("x", &p)), Trust::Confined);
        assert_eq!(
            (d.verdict, d.deciding_layer),
            (Verdict::Deny, RuleLayer::Hard)
        );
        assert!(note.unwrap().contains("LLM key"));
    }

    #[test]
    fn every_change_is_reported_both_ways() {
        let before = validate(file(
            "schema_version = 1\n[profile.claude-code]\nallow_categories = [\"tmp_execution\"]\n[profile.old]\n",
        ))
        .unwrap();
        let after = validate(file(
            "schema_version = 1\n[profile.claude-code]\nmode = \"enforce\"\nallow_categories = [\"bare_ip_fetch\"]\nmcp_tools_deny = [\"rm\"]\n[profile.claude-code.jail]\nextra_ro = [\"/opt\"]\n",
        ))
        .unwrap();
        let got: Vec<(String, String, String)> = changes(&before, &after)
            .into_iter()
            .map(|c| (c.action, c.agent_type, c.value))
            .collect();
        let want = [
            ("mode_changed", "claude-code", "enforce"),
            ("allow_category_added", "claude-code", "bare_ip_fetch"),
            ("allow_category_removed", "claude-code", "tmp_execution"),
            ("mcp_tool_deny_added", "claude-code", "rm"),
            ("jail_extra_ro_added", "claude-code", "/opt"),
            ("profile_removed", "old", ""),
        ];
        let want: Vec<(String, String, String)> = want
            .iter()
            .map(|(a, t, v)| (a.to_string(), t.to_string(), v.to_string()))
            .collect();
        assert_eq!(got, want);
        assert!(changes(&after, &after).is_empty());
    }

    // -- what the person decided -------------------------------------------

    const ID: &str = "3f9a0c1e5b7d42a8c6e1f0b2d4a69c87";
    const OTHER_ID: &str = "0000000000000000000000000000beef";

    fn checked(text: &str) -> AgentProfiles {
        parse(text.as_bytes()).unwrap_or_else(|e| panic!("{e}\n{text}"))
    }

    fn system(text: &str) -> AgentProfiles {
        merge(Some(&checked(text)), None)
    }

    #[test]
    fn an_agent_table_validates_into_a_record() {
        let p = checked(&format!(
            r#"
schema_version = 1
[profile.engineering]
allow_categories = ["tmp_execution"]
[agent.claude-code]
lifecycle = "approved"
owner = "maria"
profile = "engineering"
approved_by = "maria"
approved_at = "2026-10-17T09:00:00Z"
revoked_instances = ["{ID}"]
allow_categories = ["bare_ip_fetch"]
mcp_tools_allow = ["read_file"]
[[agent.claude-code.exception]]
instance_id = "{ID}"
category = "tmp_execution"
[[agent.claude-code.exception]]
instance_id = "{ID}"
mcp_tool = "save"
"#
        ));
        let r = p.record("claude-code").unwrap();
        assert_eq!(r.lifecycle(), Lifecycle::Approved);
        assert_eq!(r.owner.as_deref(), Some("maria"));
        assert_eq!(r.profile.as_deref(), Some("engineering"));
        assert_eq!(r.revoked_instances, [ID]);
        assert_eq!(r.allow_categories, ["bare_ip_fetch"]);
        let e = &r.exceptions[ID];
        assert_eq!(e.categories, ["tmp_execution"]);
        assert_eq!(e.mcp_tools, ["save"]);
        assert_eq!(p.lifecycle("cursor"), Lifecycle::Discovered);
    }

    #[test]
    fn an_agent_table_that_cannot_mean_one_thing_is_refused() {
        for (body, says) in [
            ("lifecycle = \"discovered\"", "unknown lifecycle"),
            ("profile = \"nope\"", "names no [profile.nope]"),
            ("owner = \"\"", "is not a name"),
            ("owner = \"a\\nb\"", "is not a name"),
            ("approved_at = \"yesterday\"", "not an RFC 3339 time"),
            ("revoked_instances = [\"../x\"]", "not an instance id"),
            ("allow_categories = [\"nope\"]", "not a signal name"),
            ("mcp_tools_allow = [\"two words\"]", "not a tool name"),
            ("color = \"red\"", "not a profiles file"),
        ] {
            let err =
                parse(format!("schema_version = 1\n[agent.claude-code]\n{body}\n").as_bytes())
                    .unwrap_err()
                    .to_string();
            assert!(err.contains(says), "{body}: {err}");
        }
        for (exception, says) in [
            (format!("instance_id = \"{ID}\""), "exactly one"),
            (
                format!("instance_id = \"{ID}\"\ncategory = \"tmp_execution\"\nmcp_tool = \"x\""),
                "exactly one",
            ),
            (
                "instance_id = \"BAD\"\ncategory = \"tmp_execution\"".to_string(),
                "not an instance id",
            ),
        ] {
            let text = format!(
                "schema_version = 1\n[agent.claude-code]\n[[agent.claude-code.exception]]\n{exception}\n"
            );
            let err = parse(text.as_bytes()).unwrap_err().to_string();
            assert!(err.contains(says), "{text}: {err}");
        }
        let err = parse(b"schema_version = 1\n[profile.general]\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("names your general rules"), "{err}");
    }

    /// An allow, by profile, by type or by instance, never reaches the hard
    /// layer: refused at load wherever it is written.
    ///
    /// FAILS ON REVERT: drop the hard check from `allowed_categories` and the
    /// agent table and the exception load.
    #[test]
    fn an_allow_of_a_hard_signal_is_refused_in_an_agent_table_and_an_exception() {
        for hard in [
            "download_and_execute",
            "guard_self_disable",
            "sensitive_credential_read",
        ] {
            for text in [
                format!("schema_version = 1\n[agent.claude-code]\nallow_categories = [\"{hard}\"]\n"),
                format!(
                    "schema_version = 1\n[agent.claude-code]\n[[agent.claude-code.exception]]\ninstance_id = \"{ID}\"\ncategory = \"{hard}\"\n"
                ),
            ] {
                let err = parse(text.as_bytes()).unwrap_err().to_string();
                assert!(err.contains("is a hard rule"), "{text}: {err}");
            }
        }
    }

    /// FAILS ON REVERT: skip the `[agent]` loop in `check_user_file` and the
    /// user's file relaxes through it.
    #[test]
    fn the_users_file_can_decide_but_never_relax_through_an_agent_table() {
        for body in [
            "allow_categories = [\"bare_ip_fetch\"]".to_string(),
            "mcp_tools_allow = [\"read_file\"]".to_string(),
            format!("[[agent.claude-code.exception]]\ninstance_id = \"{ID}\"\ncategory = \"bare_ip_fetch\""),
        ] {
            let user = checked(&format!("schema_version = 1\n[agent.claude-code]\n{body}\n"));
            let err = check_user_file(&user).unwrap_err().to_string();
            assert!(err.contains("only /etc/innerwarden"), "{body}: {err}");
        }
        let deciding = checked(&format!(
            "schema_version = 1\n[profile.strict]\ndeny_categories = [\"bare_ip_fetch\"]\n[agent.claude-code]\nlifecycle = \"revoked\"\nprofile = \"strict\"\nrevoked_instances = [\"{ID}\"]\n"
        ));
        assert_eq!(check_user_file(&deciding), Ok(()));
    }

    #[test]
    fn an_assignment_replaces_the_types_own_table_and_general_takes_it_away() {
        let text = |assignment: &str| {
            format!(
                "schema_version = 1\n[profile.claude-code]\nallow_categories = [\"tmp_execution\"]\n[profile.engineering]\nallow_categories = [\"bare_ip_fetch\"]\n[agent.claude-code]\n{assignment}\n"
            )
        };
        let own = system(&text(""));
        assert_eq!(
            own.get("claude-code").unwrap().allow_categories,
            ["tmp_execution"]
        );
        assert_eq!(
            own.get("claude-code").unwrap().source,
            Some(ProfileSource::System)
        );
        let assigned = system(&text("profile = \"engineering\""));
        assert_eq!(
            assigned.get("claude-code").unwrap().allow_categories,
            ["bare_ip_fetch"]
        );
        assert!(system(&text("profile = \"general\""))
            .get("claude-code")
            .is_none());
        // An allowance from a case is added to whatever the type gets.
        let added = system(&text(
            "profile = \"general\"\nallow_categories = [\"tmp_execution\"]\nmcp_tools_allow = [\"save\"]",
        ));
        let p = added.get("claude-code").unwrap();
        assert_eq!(p.allow_categories, ["tmp_execution"]);
        assert_eq!(p.mcp_tools_allow, ["save"]);
    }

    /// The user's file cannot take away what the system file gives, and its
    /// decisions merge with the system's without losing a revocation.
    #[test]
    fn the_users_assignment_adds_nothing_and_a_revocation_in_either_file_holds() {
        let sys = checked(
            "schema_version = 1\n[profile.engineering]\nallow_categories = [\"bare_ip_fetch\"]\n[agent.claude-code]\nlifecycle = \"approved\"\nowner = \"ops\"\nprofile = \"engineering\"\n",
        );
        let user = checked(&format!(
            "schema_version = 1\n[agent.claude-code]\nlifecycle = \"revoked\"\nowner = \"dev\"\nprofile = \"general\"\nrevoked_by = \"dev\"\nrevoked_at = \"2026-10-17T10:00:00Z\"\nrevoked_instances = [\"{ID}\"]\n"
        ));
        let merged = merge(Some(&sys), Some(&user));
        assert_eq!(
            merged.get("claude-code").unwrap().allow_categories,
            ["bare_ip_fetch"]
        );
        let r = merged.record("claude-code").unwrap();
        assert_eq!(r.lifecycle(), Lifecycle::Revoked);
        assert_eq!(
            r.owner.as_deref(),
            Some("ops"),
            "the system file's names first"
        );
        assert_eq!(r.revoked_by.as_deref(), Some("dev"));
        assert_eq!(r.revoked_instances, [ID]);
    }

    /// Revoked: refused by the hard layer at every trust and on every line,
    /// whatever the profile allows. A revoked instance is refused under any
    /// type it names.
    ///
    /// FAILS ON REVERT: leave `record.revoked` out of `hard_refused` and the
    /// allowed review runs for the confined instance.
    #[test]
    fn a_revoked_type_or_instance_is_refused_by_the_hard_layer() {
        let p = system(&format!(
            "schema_version = 1\n[profile.claude-code]\nallow_categories = [\"bare_ip_fetch\"]\n[agent.claude-code]\nlifecycle = \"revoked\"\n[agent.cursor]\nrevoked_instances = [\"{ID}\"]\n"
        ));
        let call = shell(Verdict::Review, &["bare_ip_fetch"], false);
        let quiet = shell(Verdict::Allow, &[], false);
        for trust in ALL_TRUST {
            for line_block_review in [false, true] {
                for c in [&call, &quiet] {
                    let named = Some(("claude-code", p.get("claude-code").unwrap()));
                    let out = decide_shell_in(
                        c,
                        named,
                        p.facts(Some("claude-code"), None),
                        line_block_review,
                        trust,
                    );
                    assert_eq!(
                        (out.decision.verdict, out.decision.deciding_layer),
                        (Verdict::Deny, RuleLayer::Hard),
                        "{trust:?}"
                    );
                    assert!(out.blocks);
                    assert_eq!(
                        out.note.as_deref(),
                        Some("Refused: this agent was revoked.")
                    );
                }
            }
            let out = decide_shell_in(&quiet, None, p.facts(Some("aider"), Some(ID)), false, trust);
            assert_eq!(out.decision.deciding_layer, RuleLayer::Hard);
            assert_eq!(
                out.note.as_deref(),
                Some("Refused: this instance was revoked.")
            );
        }
        assert_eq!(p.revocation(Some("cursor"), Some(OTHER_ID)), None);
        assert_eq!(p.revocation(None, None), None);
        let (d, note) = decide_tool_call_in(
            &ToolCallFacts {
                tool: "weather",
                allowed: true,
                has_alerts: false,
                charged: &[],
                hard_alert: false,
                names_llm_key: false,
            },
            None,
            Some(Revocation::AgentType),
            Trust::Confined,
        );
        assert_eq!(
            (d.verdict, d.deciding_layer),
            (Verdict::Deny, RuleLayer::Hard)
        );
        assert_eq!(note.as_deref(), Some("Refused: this agent was revoked."));
    }

    /// An exception is one instance's, and only a confined one's: the same
    /// instance id from a declared or observed caller gets the general
    /// policy, and another instance gets nothing.
    ///
    /// FAILS ON REVERT: relax the instance layer for `Observed` in
    /// `identity::decide` and the observed row turns `allow`.
    #[test]
    fn an_exception_relaxes_only_its_confined_instance() {
        let p = system(&format!(
            "schema_version = 1\n[[agent.claude-code.exception]]\ninstance_id = \"{ID}\"\ncategory = \"bare_ip_fetch\"\n"
        ));
        let call = shell(Verdict::Review, &["bare_ip_fetch"], true);
        let facts = p.facts(Some("claude-code"), Some(ID));
        assert!(facts.exception.is_some());
        let out = decide_shell_in(&call, None, facts, true, Trust::Confined);
        assert_eq!(
            (out.decision.verdict, out.decision.deciding_layer),
            (Verdict::Allow, RuleLayer::Instance)
        );
        assert!(!out.blocks);
        assert!(out
            .note
            .unwrap()
            .contains("exception for this confined instance"));
        for trust in [Trust::Declared, Trust::Observed] {
            let out = decide_shell_in(&call, None, facts, true, trust);
            assert_eq!(
                (out.decision.verdict, out.decision.deciding_layer),
                (Verdict::Review, RuleLayer::General),
                "{trust:?}"
            );
            assert!(out.blocks);
        }
        let other = p.facts(Some("claude-code"), Some(OTHER_ID));
        assert_eq!(other.exception, None);
        // An argument from a tool result is not relaxed, and a general deny
        // is never lifted.
        let mut tainted = call;
        tainted.tainted = true;
        assert!(decide_shell_in(&tainted, None, facts, true, Trust::Confined).blocks);
        let deny = shell(Verdict::Deny, &["bare_ip_fetch"], true);
        assert!(decide_shell_in(&deny, None, facts, false, Trust::Confined).blocks);
    }

    // -- writing a decision --------------------------------------------------

    const STAMP: Stamp<'static> = Stamp {
        by: "maria",
        at: "2026-10-17T09:00:00Z",
    };

    #[test]
    fn an_approval_is_written_into_a_new_or_existing_file_keeping_its_comments() {
        let fresh = edit_approve("", "claude-code", Some("maria"), Some("general"), STAMP).unwrap();
        let p = checked(&fresh);
        let r = p.record("claude-code").unwrap();
        assert_eq!(r.lifecycle(), Lifecycle::Approved);
        assert_eq!(r.approved_by.as_deref(), Some("maria"));
        assert_eq!(r.profile.as_deref(), Some("general"));

        let hand = "# ours, keep this\nschema_version = 1\n\n[profile.claude-code] # note\ndeny_categories = [\"bare_ip_fetch\"]\n";
        let edited = edit_approve(hand, "claude-code", None, None, STAMP).unwrap();
        assert!(edited.contains("# ours, keep this"), "{edited}");
        assert!(edited.contains("# note"), "{edited}");
        let p = checked(&edited);
        assert_eq!(p.lifecycle("claude-code"), Lifecycle::Approved);
        assert_eq!(p.types["claude-code"].deny_categories, ["bare_ip_fetch"]);
    }

    /// Revoking keeps the history: who approved it, its owner and profile
    /// stay, and an instance revocation adds to the list.
    #[test]
    fn a_revocation_keeps_what_was_decided_before() {
        let approved =
            edit_approve("", "claude-code", Some("ops"), Some("general"), STAMP).unwrap();
        let revoked = revoke(
            &approved,
            "claude-code",
            None,
            Stamp {
                by: "dev",
                at: "2026-10-18T09:00:00Z",
            },
        )
        .unwrap();
        let revoked = revoke(&revoked, "claude-code", Some(ID), STAMP).unwrap();
        let revoked = revoke(&revoked, "claude-code", Some(ID), STAMP).unwrap();
        let p = checked(&revoked);
        let r = p.record("claude-code").unwrap();
        assert_eq!(r.lifecycle(), Lifecycle::Revoked);
        assert_eq!(r.owner.as_deref(), Some("ops"));
        assert_eq!(r.approved_by.as_deref(), Some("maria"));
        assert_eq!(r.approved_at.as_deref(), Some("2026-10-17T09:00:00Z"));
        assert_eq!(r.revoked_by.as_deref(), Some("dev"));
        assert_eq!(r.profile.as_deref(), Some("general"));
        assert_eq!(r.revoked_instances, [ID], "added once");
    }

    #[test]
    fn an_allow_is_added_to_the_type_or_as_an_exception_once() {
        let rule = AllowRule::Category("bare_ip_fetch".into());
        let typed = add_allow("", "claude-code", &rule, None).unwrap();
        let typed = add_allow(&typed, "claude-code", &rule, None).unwrap();
        let typed = add_allow(
            &typed,
            "claude-code",
            &AllowRule::McpTool("save".into()),
            None,
        )
        .unwrap();
        let p = checked(&typed);
        assert_eq!(
            p.record("claude-code").unwrap().allow_categories,
            ["bare_ip_fetch"]
        );
        assert_eq!(p.record("claude-code").unwrap().mcp_tools_allow, ["save"]);
        let one = add_allow("", "claude-code", &rule, Some(ID)).unwrap();
        let one = add_allow(&one, "claude-code", &rule, Some(ID)).unwrap();
        assert_eq!(
            one.matches("[[agent.claude-code.exception]]").count(),
            1,
            "{one}"
        );
        assert_eq!(
            checked(&one).record("claude-code").unwrap().exceptions[ID].categories,
            ["bare_ip_fetch"]
        );
        let assigned = set_assignment(&typed, "claude-code", "general").unwrap();
        assert_eq!(
            checked(&assigned)
                .record("claude-code")
                .unwrap()
                .profile
                .as_deref(),
            Some("general")
        );
    }

    /// An edit never writes what the loader would refuse unnoticed: an allow
    /// of a hard signal edits the text, and the result does not load.
    #[test]
    fn an_edited_hard_allow_does_not_load() {
        for instance in [None, Some(ID)] {
            let text = add_allow(
                "",
                "claude-code",
                &AllowRule::Category("guard_self_disable".into()),
                instance,
            )
            .unwrap();
            assert!(parse(text.as_bytes())
                .unwrap_err()
                .to_string()
                .contains("is a hard rule"));
        }
        assert!(edit_approve("", "Not An Id", None, None, STAMP).is_err());
        assert!(edit_approve("agent = 3\nschema_version = 1\n", "x", None, None, STAMP).is_err());
    }

    #[test]
    fn relaxes_names_every_widening_and_no_tightening() {
        let base = profile(&["bare_ip_fetch"], &["tmp_execution"]);
        let widen = |f: &dyn Fn(&mut AgentProfile)| {
            let mut p = base.clone();
            f(&mut p);
            relaxes(Some(&base), Some(&p))
        };
        assert!(widen(&|p| p.allow_categories.push("x".into())));
        assert!(widen(&|p| p.mcp_tools_allow.push("x".into())));
        assert!(widen(&|p| p.deny_categories.clear()));
        assert!(widen(&|p| p.mode = Some(ProfileMode::Enforce)));
        assert!(widen(&|p| p.jail.extra_ro.push("/opt".into())));
        assert!(widen(&|p| p.jail.project_rw = Some("/srv".into())));
        assert!(!widen(&|p| p.deny_categories.push("x".into())));
        assert!(!widen(&|p| p.allow_categories.clear()));
        assert!(!widen(&|p| p.mode = Some(ProfileMode::BlockReview)));
        assert!(!widen(&|p| p.jail.deny_read.push("x".into())));
        assert!(
            relaxes(None, Some(&base)),
            "an allow over the general rules"
        );
        assert!(
            relaxes(Some(&base), None),
            "back to the general rules drops a refusal"
        );
        assert!(
            !relaxes(Some(&profile(&["bare_ip_fetch"], &[])), None),
            "back to the general rules from an allow only"
        );
        assert!(!relaxes(None, Some(&profile(&[], &["x"]))));
    }

    #[test]
    fn describe_says_each_rule_in_a_line() {
        assert_eq!(describe(None), ["Your general rules, nothing added."]);
        let mut p = profile(&["bare_ip_fetch"], &["tmp_execution"]);
        p.mode = Some(ProfileMode::BlockReview);
        assert_eq!(
            describe(Some(&p)),
            [
                "Runs without review, when confined: bare_ip_fetch.",
                "Refused: tmp_execution.",
                "A review is refused too.",
            ]
        );
    }

    #[test]
    fn a_change_to_a_decision_is_reported_on_its_layer() {
        let before = checked(&format!(
            "schema_version = 1\n[agent.claude-code]\nlifecycle = \"approved\"\n[[agent.claude-code.exception]]\ninstance_id = \"{ID}\"\ncategory = \"bare_ip_fetch\"\n"
        ));
        let after = checked(&format!(
            "schema_version = 1\n[agent.claude-code]\nlifecycle = \"revoked\"\nprofile = \"general\"\nrevoked_instances = [\"{ID}\"]\n"
        ));
        let got: Vec<(RuleLayer, String, String)> = changes(&before, &after)
            .into_iter()
            .map(|c| (c.layer, c.action, c.value))
            .collect();
        assert_eq!(
            got,
            [
                (
                    RuleLayer::AgentType,
                    "lifecycle_changed".to_string(),
                    "revoked".to_string()
                ),
                (
                    RuleLayer::AgentType,
                    "profile_assigned".to_string(),
                    "general".to_string()
                ),
                (
                    RuleLayer::Instance,
                    "instance_revoked".to_string(),
                    ID.to_string()
                ),
                (
                    RuleLayer::Instance,
                    "exception_category_removed".to_string(),
                    format!("{ID} bare_ip_fetch")
                ),
            ]
        );
    }
}
