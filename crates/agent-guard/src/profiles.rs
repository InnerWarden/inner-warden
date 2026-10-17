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
//! it.
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

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::identity::{decide, is_hard_signal, Decision, LayerRule, Layers, Trust, Verdict};
use crate::mcp::SIGNAL_NAMES;

/// The file's name, in both places.
pub const PROFILES_FILE: &str = "agent-profiles.toml";

/// The system-wide file.
pub const SYSTEM_PROFILES_PATH: &str = "/etc/innerwarden/agent-profiles.toml";

/// The user's file, relative to the home.
pub const USER_PROFILES_PATH: &str = ".config/innerwarden/agent-profiles.toml";

/// The schema this build reads.
pub const PROFILES_SCHEMA: u32 = 1;

/// The largest file read. A file of profiles is a few kilobytes.
pub const MAX_PROFILES_BYTES: usize = 64 * 1024;

const MAX_TYPES: usize = 64;
const MAX_ENTRIES: usize = 128;
const MAX_TOOL_NAME_BYTES: usize = 128;
const MAX_PATH_BYTES: usize = 4096;
const MAX_GLOB_BYTES: usize = 255;

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
}

/// Every type's profile, checked, by agent type.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentProfiles {
    pub types: BTreeMap<String, AgentProfile>,
}

impl AgentProfiles {
    /// The profile for `agent_type`, if there is one.
    pub fn get(&self, agent_type: &str) -> Option<&AgentProfile> {
        self.types.get(agent_type)
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
/// Refused, with the reason: another schema, an agent type that is not an
/// agent id, a mode other than `enforce` or `block-review`, a category that is
/// not a signal name, an allowed category that is a hard rule, a category or
/// a tool both allowed and denied, a tool name or a path that is not one, and
/// `net = false`.
pub fn validate(file: ProfilesFile) -> Result<AgentProfiles, ProfileError> {
    if file.schema_version != PROFILES_SCHEMA {
        return Err(ProfileError(format!(
            "unsupported schema_version {} (this version reads {PROFILES_SCHEMA})",
            file.schema_version
        )));
    }
    if file.profile.len() > MAX_TYPES {
        return Err(ProfileError(format!(
            "{} profiles, more than the {MAX_TYPES} a file may hold",
            file.profile.len()
        )));
    }
    let mut types = BTreeMap::new();
    for (agent_type, entry) in file.profile {
        if !crate::hook::is_agent_id(&agent_type) {
            return Err(ProfileError(format!(
                "`{agent_type}` is not an agent type: lowercase letters, digits, `-` and `_`, \
                 at most 64"
            )));
        }
        let profile = validate_entry(&agent_type, entry)?;
        types.insert(agent_type, profile);
    }
    Ok(AgentProfiles { types })
}

fn validate_entry(agent_type: &str, entry: ProfileEntry) -> Result<AgentProfile, ProfileError> {
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
        Some(jail) => validate_jail(agent_type, jail)?,
    };
    Ok(AgentProfile {
        mode,
        allow_categories,
        deny_categories,
        mcp_tools_allow,
        mcp_tools_deny,
        jail,
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

/// A glob relative to the project, with no `..` step.
fn is_project_glob(glob: &str) -> bool {
    !glob.is_empty()
        && glob.len() <= MAX_GLOB_BYTES
        && !glob.starts_with(['/', '~'])
        && !glob.chars().any(char::is_control)
        && glob.split('/').all(|step| step != "..")
}

fn validate_jail(agent_type: &str, jail: JailEntry) -> Result<JailProfile, ProfileError> {
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
    })
}

/// Refuse a relaxation in the user's file (see the module notes): an
/// `allow_categories` or `mcp_tools_allow` entry, or `mode = "enforce"`.
pub fn check_user_file(profiles: &AgentProfiles) -> Result<(), ProfileError> {
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
pub fn merge(system: Option<&AgentProfiles>, user: Option<&AgentProfiles>) -> AgentProfiles {
    let mut types: BTreeMap<String, AgentProfile> = BTreeMap::new();
    for profiles in [system, user].into_iter().flatten() {
        for (agent_type, profile) in &profiles.types {
            let merged = types.entry(agent_type.clone()).or_default();
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
        }
    }
    AgentProfiles { types }
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
    let hard_signal = call.blocks_today && call.charged.iter().any(|s| is_hard_signal(s));
    let agent_type = profile
        .and_then(|(_, p)| command_rule(p, call.charged))
        .filter(|rule| !(call.tainted && *rule == LayerRule::Allow));
    let decision = decide(
        Layers {
            hard_refused: call.names_llm_key || hard_signal,
            general: call.general,
            agent_type,
            instance: None,
        },
        trust,
    );
    let review = review_blocks(line_block_review, profile.and_then(|(_, p)| p.mode), trust);
    let blocks = match decision.verdict {
        Verdict::Deny => true,
        Verdict::Review => review,
        Verdict::Allow => false,
    };
    let name = profile.map(|(name, _)| name).unwrap_or("");
    let note = match (decision.deciding_layer, decision.verdict) {
        (crate::identity::RuleLayer::Hard, _) if call.names_llm_key && !hard_signal => {
            Some("hard rule: the command reaches the guard's own LLM key".to_string())
        }
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
    }
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
            hard_refused: call.names_llm_key || hard_rule,
            general,
            agent_type,
            instance: None,
        },
        trust,
    );
    let name = profile.map(|(name, _)| name).unwrap_or("");
    let note = match (decision.deciding_layer, decision.verdict) {
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyProfile {
    /// Profiles are in force. `profile` is the one for the proxy's agent type
    /// (`None` when it has none: the hard layer still holds), `trust` the
    /// level the proxy knows its instance at.
    Active {
        agent_type: Option<String>,
        profile: Option<AgentProfile>,
        trust: Trust,
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
    pub action: String,
    pub agent_type: String,
    pub value: String,
}

/// Every change from `before` to `after`, additions and removals both, so the
/// line stream can be replayed into what was in force at any moment.
pub fn changes(before: &AgentProfiles, after: &AgentProfiles) -> Vec<ProfileChange> {
    let mut out = Vec::new();
    let empty = AgentProfile::default();
    let mut push = |action: &str, agent_type: &str, value: &str| {
        out.push(ProfileChange {
            action: action.to_string(),
            agent_type: agent_type.to_string(),
            value: value.to_string(),
        });
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
        let lists: [(&str, &[String], &[String]); 6] = [
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
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::RuleLayer;

    fn file(text: &str) -> ProfilesFile {
        toml::from_str(text).expect("parses")
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
            ("schema_version = 2\n", "unsupported schema_version 2"),
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
}
