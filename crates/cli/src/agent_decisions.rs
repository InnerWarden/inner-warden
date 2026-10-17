//! `innerwarden agents approve|profile|allow|revoke`: the person's decisions
//! about a type of agent, and what the local dashboard shows of them.
//!
//! The local dashboard is read-only by design (every `/api/` route answers
//! GET only), so a decision is a verb run by a person at their own terminal,
//! never a request a web page or a program could send. These verbs write
//! `[agent.<type>]` into a file of profiles (see
//! `innerwarden_agent_guard::profiles`): the user's own, or the system one
//! with `--system` as root. The rules that file holds stay where they were:
//!
//! * a relaxation (an allowance, a profile that lets more through) is
//!   honoured only for an instance that runs confined, and only from the
//!   system file; the verbs refuse to write one into the user's file;
//! * an allowance never names a hard signal;
//! * a revocation keeps everything recorded before it.
//!
//! Every decision is confirmed at the terminal. A relaxation asks the person
//! to type the agent's name; the others take `y` or `--yes`. Without a
//! terminal the verb changes nothing and exits 2.
//!
//! This module is pure: the arguments, the refusals, the effect a change
//! has, and the words for each. The reads, the confirmation and the write are
//! in `agent_decisions_io`.

use innerwarden_agent_guard::identity::{is_instance_id, Lifecycle, Trust};
use innerwarden_agent_guard::mcp::SIGNAL_NAMES;
use innerwarden_agent_guard::profiles::{
    self, is_person_name, AgentProfile, AgentProfiles, AllowRule, ProfileSource, GENERAL_PROFILE,
};
use serde::Serialize;
use serde_json::{json, Value};

/// The four verbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Approve,
    Profile,
    Allow,
    Revoke,
}

impl Verb {
    pub fn from_word(word: &str) -> Option<Self> {
        match word {
            "approve" => Some(Verb::Approve),
            "profile" => Some(Verb::Profile),
            "allow" => Some(Verb::Allow),
            "revoke" => Some(Verb::Revoke),
            _ => None,
        }
    }

    /// The action's name in the audit line and the response, the same word
    /// the Enterprise dashboard uses.
    pub fn skill_id(self) -> &'static str {
        match self {
            Verb::Approve => "agent_approve",
            Verb::Profile => "agent_profile",
            Verb::Allow => "agent_allow",
            Verb::Revoke => "agent_revoke",
        }
    }
}

/// One verb, as its arguments say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub verb: Verb,
    pub agent: String,
    pub owner: Option<String>,
    /// `approve --profile <name>`, or the name `profile` assigns.
    pub profile: Option<String>,
    pub rule: Option<AllowRule>,
    pub instance: Option<String>,
    /// Write the system file (root only) instead of the user's.
    pub system: bool,
    pub yes: bool,
    pub json: bool,
}

/// The usage line of each verb.
pub fn usage() -> String {
    let p = crate::prog();
    format!(
        "{p} agents approve <agent> [--owner <name>] [--profile <name>] [--system] [--yes] [--json]\n\
         {p} agents profile <agent> <name|general> [--system] [--yes] [--json]\n\
         {p} agents allow <agent> (--category <signal> | --mcp-tool <name>) [--instance <id>] --system [--json]\n\
         {p} agents revoke <agent> [--instance <id>] [--system] [--yes] [--json]"
    )
}

/// Read the arguments after `agents`. The verb must come first, so
/// `agents --json approve` is not one of these verbs.
pub fn parse(rest: &[String]) -> Result<Request, String> {
    let verb = rest
        .first()
        .and_then(|word| Verb::from_word(word))
        .ok_or("not an agent decision verb")?;
    let mut request = Request {
        verb,
        agent: String::new(),
        owner: None,
        profile: None,
        rule: None,
        instance: None,
        system: false,
        yes: false,
        json: false,
    };
    let mut positional: Vec<&str> = Vec::new();
    let mut args = rest[1..].iter();
    let value = |args: &mut std::slice::Iter<'_, String>, flag: &str| -> Result<String, String> {
        args.next()
            .filter(|v| !v.starts_with("--"))
            .cloned()
            .ok_or_else(|| format!("{flag} needs a value"))
    };
    while let Some(arg) = args.next() {
        match (verb, arg.as_str()) {
            (_, "--system") => request.system = true,
            (_, "--json") => request.json = true,
            (Verb::Approve | Verb::Profile | Verb::Revoke, "--yes") => request.yes = true,
            (Verb::Approve, "--owner") => request.owner = Some(value(&mut args, "--owner")?),
            (Verb::Approve, "--profile") => {
                request.profile = Some(value(&mut args, "--profile")?);
            }
            (Verb::Allow, "--category") if request.rule.is_none() => {
                request.rule = Some(AllowRule::Category(value(&mut args, "--category")?));
            }
            (Verb::Allow, "--mcp-tool") if request.rule.is_none() => {
                request.rule = Some(AllowRule::McpTool(value(&mut args, "--mcp-tool")?));
            }
            (Verb::Allow | Verb::Revoke, "--instance") => {
                request.instance = Some(value(&mut args, "--instance")?);
            }
            (_, flag) if flag.starts_with('-') => {
                return Err(format!("`{flag}` is not an option of `agents {}`", rest[0]));
            }
            (_, word) => positional.push(word),
        }
    }
    let wanted = if verb == Verb::Profile { 2 } else { 1 };
    if positional.len() != wanted {
        return Err(format!(
            "`agents {}` takes {}",
            rest[0],
            if wanted == 2 {
                "an agent and a profile name"
            } else {
                "one agent"
            }
        ));
    }
    request.agent = positional[0].to_string();
    if verb == Verb::Profile {
        request.profile = Some(positional[1].to_string());
    }
    if verb == Verb::Allow && request.rule.is_none() {
        return Err("`agents allow` needs --category <signal> or --mcp-tool <name>".into());
    }
    Ok(request)
}

/// A refusal: the closed code (the same word on stderr and in `--json`) and
/// the sentence for the person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: &'static str,
    pub sentence: String,
}

fn refuse(code: &'static str, sentence: impl Into<String>) -> Refusal {
    Refusal {
        code,
        sentence: sentence.into(),
    }
}

/// An instance the launcher recorded for this user, as the dashboard and the
/// verbs count it. The trust is what the hook inside that jail would judge
/// from the launcher's record and the jail's namespace: a label for a count
/// and a check before writing, never what a decision is made at (the hook
/// judges again, from inside, every time).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalInstance {
    pub instance_id: String,
    pub agent_type: String,
    /// The jail process still runs: its pid AND its start time match.
    pub live: bool,
    pub trust: Trust,
}

/// Live instances of `agent`: confined, and the others.
pub fn count(instances: &[LocalInstance], agent: &str) -> (usize, usize) {
    let live = instances.iter().filter(|i| i.live && i.agent_type == agent);
    let confined = live.clone().filter(|i| i.trust == Trust::Confined).count();
    (confined, live.count() - confined)
}

/// Everything a verb decides from, all read by the caller.
#[derive(Debug, Clone, Copy)]
pub struct Facts<'a> {
    /// The file the verb would write, as written there.
    pub target: &'a AgentProfiles,
    /// What is in force now, both files together.
    pub merged: &'a AgentProfiles,
    /// The agent is one this product knows, or the files already name it.
    pub known_agent: bool,
    /// This process runs as root.
    pub is_root: bool,
    pub instances: &'a [LocalInstance],
}

/// What a verb will write, once the person confirms it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Edit {
    Approve {
        owner: String,
        profile: Option<String>,
    },
    Assign(String),
    Allow {
        rule: AllowRule,
        instance: Option<String>,
    },
    Revoke {
        instance: Option<String>,
    },
}

/// The name of the profile in force for `agent` (`None`: the general rules).
pub fn profile_name(merged: &AgentProfiles, agent: &str) -> Option<String> {
    match merged.record(agent).and_then(|r| r.profile.as_deref()) {
        Some(GENERAL_PROFILE) => merged.get(agent).map(|_| agent.to_string()),
        Some(name) => Some(name.to_string()),
        None => merged.get(agent).map(|_| agent.to_string()),
    }
}

/// How a profile is named to a person.
pub fn profile_label(name: Option<&str>) -> String {
    match name {
        None | Some(GENERAL_PROFILE) => "General rules".to_string(),
        Some(name) => name.to_string(),
    }
}

/// PURE. The refusals a verb meets before anything is asked or written, in
/// a fixed order: who may write the file, the agent, the instance, the
/// profile, the agent's state, a hard rule, the instance's trust, and the
/// file a relaxation needs. `Ok` is the edit to make.
pub fn plan(request: &Request, facts: &Facts<'_>, operator: &str) -> Result<Edit, Refusal> {
    let agent = request.agent.as_str();
    if request.system && !facts.is_root {
        return Err(refuse(
            "not_root",
            format!(
                "Only root writes {}: run it with sudo.",
                profiles::SYSTEM_PROFILES_PATH
            ),
        ));
    }
    if !innerwarden_agent_guard::hook::is_agent_id(agent) || !facts.known_agent {
        return Err(refuse(
            "unknown_agent",
            format!("No agent named `{agent}` is known here."),
        ));
    }
    if let Some(id) = &request.instance {
        if !is_instance_id(id) {
            return Err(refuse(
                "bad_request",
                format!("`{id}` is not an instance id."),
            ));
        }
        let known = facts
            .instances
            .iter()
            .any(|i| &i.instance_id == id && i.agent_type == agent);
        let revoked_before = facts
            .merged
            .record(agent)
            .is_some_and(|r| r.revoked_instances.contains(id));
        if !known && !revoked_before {
            return Err(refuse(
                "unknown_instance",
                format!("No instance {} of {agent} was started here.", short(id)),
            ));
        }
    }
    let revoked = facts.merged.lifecycle(agent) == Lifecycle::Revoked;
    match request.verb {
        Verb::Approve => {
            if let Some(name) = &request.profile {
                known_profile(facts.target, name, request.system)?;
            }
            if revoked {
                return Err(refuse(
                    "revoked",
                    "A revoked agent stays revoked in this version.",
                ));
            }
            if facts.merged.lifecycle(agent) == Lifecycle::Approved {
                return Err(refuse(
                    "already_approved",
                    format!("{agent} is already approved."),
                ));
            }
            let owner = request
                .owner
                .clone()
                .unwrap_or_else(|| operator.to_string());
            if !is_person_name(&owner) {
                return Err(refuse(
                    "bad_request",
                    "An owner is a name of 1 to 64 characters.",
                ));
            }
            Ok(Edit::Approve {
                owner,
                profile: request.profile.clone(),
            })
        }
        Verb::Profile => {
            let name = request.profile.clone().unwrap_or_default();
            known_profile(facts.target, &name, request.system)?;
            if revoked {
                return Err(refuse("revoked", format!("{agent} was revoked.")));
            }
            Ok(Edit::Assign(name))
        }
        Verb::Allow => {
            let rule = request.rule.clone().ok_or_else(|| {
                refuse(
                    "bad_request",
                    "Name a --category or an --mcp-tool to allow.",
                )
            })?;
            match &rule {
                AllowRule::Category(name) if !SIGNAL_NAMES.contains(&name.as_str()) => {
                    return Err(refuse(
                        "bad_request",
                        format!(
                            "`{name}` is not a signal name. A category is one of: {}",
                            SIGNAL_NAMES.join(", ")
                        ),
                    ))
                }
                AllowRule::McpTool(name)
                    if name.is_empty()
                        || name.len() > 128
                        || name.chars().any(|c| c.is_control() || c.is_whitespace()) =>
                {
                    return Err(refuse(
                        "bad_request",
                        format!("{name:?} is not a tool name."),
                    ))
                }
                _ => {}
            }
            if revoked {
                return Err(refuse("revoked", format!("{agent} was revoked.")));
            }
            if let AllowRule::Category(name) = &rule {
                if innerwarden_agent_guard::identity::is_hard_signal(name) {
                    return Err(refuse(
                        "hard_rule",
                        format!("`{name}` is a product rule no setting changes."),
                    ));
                }
                if facts
                    .merged
                    .get(agent)
                    .is_some_and(|p| p.deny_categories.contains(name))
                {
                    return Err(refuse(
                        "bad_request",
                        format!("The {agent} profile refuses `{name}`; change the profile first."),
                    ));
                }
            }
            if let Some(id) = &request.instance {
                let confined = facts
                    .instances
                    .iter()
                    .any(|i| &i.instance_id == id && i.live && i.trust == Trust::Confined);
                if !confined {
                    return Err(refuse(
                        "not_confined",
                        "An exception applies only to an instance that runs confined.",
                    ));
                }
            }
            if !request.system {
                return Err(needs_system_file());
            }
            Ok(Edit::Allow {
                rule,
                instance: request.instance.clone(),
            })
        }
        Verb::Revoke => {
            let already = match &request.instance {
                None => revoked,
                Some(id) => facts
                    .merged
                    .record(agent)
                    .is_some_and(|r| r.revoked_instances.contains(id)),
            };
            if already {
                return Err(refuse(
                    "revoked",
                    match &request.instance {
                        None => format!("{agent} is already revoked."),
                        Some(id) => format!("Instance {} is already revoked.", short(id)),
                    },
                ));
            }
            Ok(Edit::Revoke {
                instance: request.instance.clone(),
            })
        }
    }
}

fn needs_system_file() -> Refusal {
    refuse(
        "needs_system_file",
        format!(
            "Only {} may relax a rule, so a relaxation is never in a file an agent's account \
             can write: run it with sudo and --system.",
            profiles::SYSTEM_PROFILES_PATH
        ),
    )
}

fn known_profile(target: &AgentProfiles, name: &str, system: bool) -> Result<(), Refusal> {
    if name == GENERAL_PROFILE || target.types.contains_key(name) {
        return Ok(());
    }
    Err(refuse(
        "unknown_profile",
        format!(
            "No profile named `{name}` in {}. A type is given a profile of the file it is \
             written in{}.",
            if system {
                profiles::SYSTEM_PROFILES_PATH.to_string()
            } else {
                "your file".to_string()
            },
            if system {
                ""
            } else {
                "; for one in the system file, add --system"
            }
        ),
    ))
}

/// The first 8 characters of an instance id, as a person reads it.
pub fn short(id: &str) -> &str {
    id.get(..8).unwrap_or(id)
}

/// PURE. Write `edit` into the file's text.
pub fn apply(
    text: &str,
    request: &Request,
    edit: &Edit,
    stamp: profiles::Stamp<'_>,
) -> Result<String, String> {
    let agent = request.agent.as_str();
    match edit {
        Edit::Approve { owner, profile } => {
            profiles::edit_approve(text, agent, Some(owner), profile.as_deref(), stamp)
        }
        Edit::Assign(name) => profiles::set_assignment(text, agent, name),
        Edit::Allow { rule, instance } => {
            profiles::add_allow(text, agent, rule, instance.as_deref())
        }
        Edit::Revoke { instance } => profiles::revoke(text, agent, instance.as_deref(), stamp),
    }
    .map_err(|error| error.to_string())
}

/// How the person confirms a change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirm {
    /// `y` at the terminal, or `--yes`.
    YesNo,
    /// The agent's name typed at the terminal; `--yes` does not do it.
    TypedName,
}

/// What a change does, said before it is made and recorded after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effect {
    pub confirm: Confirm,
    /// What the person is asked to confirm.
    pub before: String,
    /// The line for the person and the audit, once written.
    pub done: String,
    pub relaxes: bool,
    pub profile_before: Option<String>,
    pub profile_after: Option<String>,
    pub scope: &'static str,
    pub confined: usize,
    pub other: usize,
}

fn instances_word(n: usize) -> &'static str {
    if n == 1 {
        "instance"
    } else {
        "instances"
    }
}

/// The sentence every relaxation carries.
pub fn applies_sentence(confined: usize, other: usize) -> String {
    format!(
        "Applies only to instances that run confined; the others keep your general rules. \
         {confined} confined and {other} other {} today.",
        instances_word(other)
    )
}

/// PURE. The effect of `edit`, from what is in force before and after it.
/// A change that lets the agent do more is a relaxation and is confirmed by
/// typing the agent's name.
pub fn effect(
    request: &Request,
    edit: &Edit,
    before: &AgentProfiles,
    after: &AgentProfiles,
    instances: &[LocalInstance],
    by: &str,
) -> Effect {
    let agent = request.agent.as_str();
    let (confined, other) = count(instances, agent);
    let rules = |p: &AgentProfiles| -> Option<AgentProfile> { p.get(agent).cloned() };
    let relaxes = profiles::relaxes(rules(before).as_ref(), rules(after).as_ref());
    let profile_before = profile_name(before, agent);
    let profile_after = profile_name(after, agent);
    let label_before = profile_label(profile_before.as_deref());
    let label_after = profile_label(profile_after.as_deref());
    let applies = applies_sentence(confined, other);
    let target = |instance: &Option<String>| match instance {
        Some(id) => format!("instance {}", short(id)),
        None => agent.to_string(),
    };
    let (before_text, done, scope) = match edit {
        Edit::Approve { owner, .. } => (
            format!(
                "Approve {agent}, owner {owner}, profile {label_after}. Approving does not \
                 change how far it is trusted: that comes from how it runs.{}",
                if relaxes {
                    format!(" {applies}")
                } else {
                    String::new()
                }
            ),
            format!("{by} approved {agent}, owner {owner}, profile {label_after}."),
            "agent_type",
        ),
        Edit::Assign(_) => (
            format!(
                "Change the {agent} profile from {label_before} to {label_after}. {}",
                if relaxes {
                    applies.clone()
                } else {
                    "It is held to more, or to the same, from its next action.".to_string()
                }
            ),
            format!(
                "{by} changed the {agent} profile from {label_before} to {label_after}. \
                 Applies to {confined} confined {}.",
                instances_word(confined)
            ),
            "agent_type",
        ),
        Edit::Allow { rule, instance } => {
            let whom = if instance.is_some() {
                "this instance only"
            } else {
                "confined instances"
            };
            (
                format!(
                    "Allow {} for {agent} ({whom}). Applies only to instances that run \
                     confined; the others keep your general rules. {confined} run confined now.",
                    rule.value()
                ),
                format!("{by} allowed {} for {agent} ({whom}).", rule.value()),
                if instance.is_some() {
                    "instance"
                } else {
                    "agent_type"
                },
            )
        }
        Edit::Revoke { instance } => (
            format!(
                "Revoke {}. No new actions from it. Its history stays. Instances that run \
                 confined are refused by their hook. An agent that gives another name is held \
                 to your general rules, not stopped.",
                target(instance)
            ),
            format!("{by} revoked {}. Its history stays.", target(instance)),
            if instance.is_some() {
                "instance"
            } else {
                "agent_type"
            },
        ),
    };
    let confirm = match edit {
        Edit::Allow { .. } => Confirm::TypedName,
        _ if relaxes => Confirm::TypedName,
        _ => Confirm::YesNo,
    };
    Effect {
        confirm,
        before: before_text,
        done,
        relaxes,
        profile_before,
        profile_after,
        scope,
        confined,
        other,
    }
}

/// The `guard.agent_decision` line for one outcome: `result` is `success` or
/// `failure: <code>`.
pub fn audit_line(
    ts: u64,
    request: &Request,
    by: &str,
    effect: Option<&Effect>,
    result: &str,
    session: Option<String>,
) -> Value {
    let mut line = json!({
        "kind": "guard.agent_decision",
        "ts": ts,
        "action": request.verb.skill_id(),
        "agent": request.agent,
        "by": by,
        "file": if request.system { "system" } else { "user" },
        "result": result,
        "session": session,
    });
    let obj = line.as_object_mut().expect("object");
    if let Some(id) = &request.instance {
        obj.insert("instance_id".into(), json!(id));
    }
    if let Some(owner) = &request.owner {
        obj.insert("owner".into(), json!(owner));
    }
    if let Some(rule) = &request.rule {
        obj.insert("rule".into(), json!(rule));
    }
    if let Some(effect) = effect {
        obj.insert("scope".into(), json!(effect.scope));
        obj.insert(
            "profile_before".into(),
            json!(profile_label(effect.profile_before.as_deref())),
        );
        obj.insert(
            "profile_after".into(),
            json!(profile_label(effect.profile_after.as_deref())),
        );
        obj.insert("confined_instances".into(), json!(effect.confined));
        obj.insert("other_instances".into(), json!(effect.other));
    }
    line
}

/// The answer `--json` prints: the same shape as the Enterprise dashboard's
/// answer to these actions, without a second factor (the confirmation is
/// the terminal's).
pub fn response(
    request: &Request,
    outcome: Result<&Effect, &Refusal>,
    after: Option<&AgentProfiles>,
) -> Value {
    match outcome {
        Ok(effect) => {
            let lifecycle = after.map(|p| p.lifecycle(&request.agent).as_str());
            json!({
                "success": true,
                "dry_run": false,
                "message": effect.done,
                "skill_id": request.verb.skill_id(),
                "refusal": null,
                "refused": null,
                "lifecycle": lifecycle,
                "profile": {
                    "name": effect.profile_after,
                    "label": profile_label(effect.profile_after.as_deref()),
                },
                "applies": {
                    "scope": effect.scope,
                    "confined_instances": effect.confined,
                    "other_instances": effect.other,
                    "applies_from": "now",
                },
            })
        }
        Err(refusal) => json!({
            "success": false,
            "dry_run": false,
            "message": refusal.sentence,
            "skill_id": request.verb.skill_id(),
            "refusal": refusal.sentence,
            "refused": refusal.code,
            "lifecycle": null,
            "profile": null,
            "applies": null,
        }),
    }
}

// ---------------------------------------------------------------------------
// What the local dashboard shows
// ---------------------------------------------------------------------------

/// The profile of a type, as `/api/agents` shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProfileView {
    pub name: Option<String>,
    pub label: String,
    pub source: Option<&'static str>,
    pub confined_instances: usize,
    pub other_instances: usize,
    /// The hook reads the file at every call, so a change applies to the
    /// next one; a running MCP proxy reads it when it starts.
    pub applies_from: &'static str,
}

/// One command for the person, as `/api/agents` shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionStep {
    pub label: &'static str,
    pub command: String,
    pub line: &'static str,
}

/// What the dashboard reads for the identity fields of `/api/agents`. With
/// none (no profiles file and no instance ever started in a jail) the
/// payload is exactly what it was.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DashboardFacts {
    pub profiles: AgentProfiles,
    pub instances: Vec<LocalInstance>,
    /// The launcher's records, as the dashboard read them.
    pub records: Vec<crate::dashboard_identity::InstanceFacts>,
    /// What the record holds about each instance id, filled by the caller
    /// that read the record.
    pub activity: std::collections::BTreeMap<String, innerwarden_graph::InstanceActivity>,
    /// A profiles file is there and cannot be used, and why. What was
    /// decided cannot be read from it, so no row says it.
    pub profiles_problem: Option<String>,
}

/// The identity fields of one agent row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowIdentity {
    pub lifecycle: &'static str,
    /// Who made the last lifecycle change, and when (as the file has it).
    pub lifecycle_by: Option<String>,
    pub lifecycle_at: Option<String>,
    pub owner: Option<String>,
    pub profile: ProfileView,
    pub decision_steps: Vec<DecisionStep>,
}

/// PURE. The identity fields for agent `id`.
pub fn row_identity(facts: &DashboardFacts, id: &str) -> RowIdentity {
    let lifecycle = facts.profiles.lifecycle(id);
    let name = profile_name(&facts.profiles, id);
    let source = facts
        .profiles
        .get(id)
        .and_then(|p| p.source)
        .map(ProfileSource::as_str);
    let (confined, other) = count(&facts.instances, id);
    let mut steps = Vec::new();
    // The name `agents connect` steps use too: the dashboard's commands are
    // for the person's shell, where the CLI is `innerwarden`.
    let p = "innerwarden";
    if lifecycle == Lifecycle::Discovered {
        steps.push(DecisionStep {
            label: "To approve it:",
            command: format!("{p} agents approve {id}"),
            line: "You choose an owner and a profile. Approving does not change how far it is \
                   trusted: that comes from how it runs.",
        });
    }
    if lifecycle != Lifecycle::Revoked && name.is_some() {
        let system = source == Some(ProfileSource::System.as_str());
        steps.push(DecisionStep {
            label: "To hold it to your general rules only:",
            command: if system {
                format!("sudo {p} agents profile {id} {GENERAL_PROFILE} --system")
            } else {
                format!("{p} agents profile {id} {GENERAL_PROFILE}")
            },
            line: "Its profile stops applying from its next action; your general rules stay.",
        });
    }
    if lifecycle != Lifecycle::Revoked {
        steps.push(DecisionStep {
            label: "To revoke it:",
            command: format!("{p} agents revoke {id}"),
            line: "No new actions from it, and its history stays. An agent that gives another \
                   name is held to your general rules, not stopped. A jail reads only the system \
                   file: to reach the instances in one, add --system and run it with sudo.",
        });
    }
    let record = facts.profiles.record(id);
    let (by, at) = match (lifecycle, record) {
        (Lifecycle::Approved, Some(r)) => (r.approved_by.clone(), r.approved_at.clone()),
        (Lifecycle::Revoked, Some(r)) => (r.revoked_by.clone(), r.revoked_at.clone()),
        _ => (None, None),
    };
    RowIdentity {
        lifecycle: lifecycle.as_str(),
        lifecycle_by: by,
        lifecycle_at: at,
        owner: record.and_then(|r| r.owner.clone()),
        profile: ProfileView {
            label: profile_label(name.as_deref()),
            name,
            source,
            confined_instances: confined,
            other_instances: other,
            applies_from: "now",
        },
        decision_steps: steps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "3f9a0c1e5b7d42a8c6e1f0b2d4a69c87";

    fn args(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_string).collect()
    }

    fn checked(text: &str) -> AgentProfiles {
        profiles::parse(text.as_bytes()).unwrap()
    }

    fn instance(trust: Trust, live: bool) -> LocalInstance {
        LocalInstance {
            instance_id: ID.into(),
            agent_type: "claude-code".into(),
            live,
            trust,
        }
    }

    fn facts<'a>(
        target: &'a AgentProfiles,
        merged: &'a AgentProfiles,
        instances: &'a [LocalInstance],
        is_root: bool,
    ) -> Facts<'a> {
        Facts {
            target,
            merged,
            known_agent: true,
            is_root,
            instances,
        }
    }

    #[test]
    fn the_arguments_are_read_strictly() {
        let r = parse(&args(
            "approve claude-code --owner maria --profile eng --yes --json",
        ))
        .unwrap();
        assert_eq!(r.verb, Verb::Approve);
        assert_eq!(r.agent, "claude-code");
        assert_eq!(r.owner.as_deref(), Some("maria"));
        assert_eq!(r.profile.as_deref(), Some("eng"));
        assert!(r.yes && r.json && !r.system);
        let r = parse(&args("profile claude-code general")).unwrap();
        assert_eq!(r.profile.as_deref(), Some("general"));
        let r = parse(&args(&format!(
            "allow claude-code --category bare_ip_fetch --instance {ID} --system"
        )))
        .unwrap();
        assert_eq!(r.rule, Some(AllowRule::Category("bare_ip_fetch".into())));
        assert_eq!(r.instance.as_deref(), Some(ID));
        for bad in [
            "approve",
            "approve a b",
            "profile claude-code",
            "allow claude-code",
            "allow claude-code --category a --mcp-tool b",
            "allow claude-code --category bare_ip_fetch --yes",
            "approve claude-code --instance x",
            "revoke claude-code --owner x",
            "approve claude-code --owner",
            "list",
        ] {
            assert!(parse(&args(bad)).is_err(), "{bad}");
        }
    }

    /// An allowance for one instance is written only for an instance that
    /// runs confined now; any other is refused before anything is asked.
    ///
    /// FAILS ON REVERT: drop the `Trust::Confined` condition from the
    /// `not_confined` check in `plan` and the observed and declared rows are
    /// planned.
    #[test]
    fn an_exception_is_planned_only_for_a_confined_instance() {
        let none = AgentProfiles::default();
        let request = parse(&args(&format!(
            "allow claude-code --category bare_ip_fetch --instance {ID} --system"
        )))
        .unwrap();
        for (instance, planned) in [
            (instance(Trust::Confined, true), true),
            (instance(Trust::Observed, true), false),
            (instance(Trust::Declared, true), false),
            (instance(Trust::Confined, false), false),
        ] {
            let list = [instance.clone()];
            let got = plan(&request, &facts(&none, &none, &list, true), "maria");
            if planned {
                assert_eq!(
                    got,
                    Ok(Edit::Allow {
                        rule: AllowRule::Category("bare_ip_fetch".into()),
                        instance: Some(ID.into())
                    })
                );
            } else {
                assert_eq!(got.unwrap_err().code, "not_confined", "{instance:?}");
            }
        }
    }

    /// An allow can never touch the hard layer, and a relaxation is never
    /// written into a file the agent's account can write.
    ///
    /// FAILS ON REVERT: drop the `is_hard_signal` check in `plan` and the
    /// floor signal is planned.
    #[test]
    fn an_allow_of_a_hard_signal_or_into_the_users_file_is_refused() {
        let none = AgentProfiles::default();
        let list = [instance(Trust::Confined, true)];
        for hard in ["download_and_execute", "guard_self_disable"] {
            let request = parse(&args(&format!(
                "allow claude-code --category {hard} --system"
            )))
            .unwrap();
            let refusal = plan(&request, &facts(&none, &none, &list, true), "m").unwrap_err();
            assert_eq!(refusal.code, "hard_rule", "{hard}");
        }
        let user = parse(&args("allow claude-code --category bare_ip_fetch")).unwrap();
        assert_eq!(
            plan(&user, &facts(&none, &none, &list, false), "m")
                .unwrap_err()
                .code,
            "needs_system_file"
        );
        let unknown = parse(&args("allow claude-code --category curl_to_bash --system")).unwrap();
        assert_eq!(
            plan(&unknown, &facts(&none, &none, &list, true), "m")
                .unwrap_err()
                .code,
            "bad_request"
        );
        let not_root = parse(&args("allow claude-code --category bare_ip_fetch --system")).unwrap();
        assert_eq!(
            plan(&not_root, &facts(&none, &none, &list, false), "m")
                .unwrap_err()
                .code,
            "not_root"
        );
    }

    #[test]
    fn the_refusals_by_state_come_before_anything_is_asked() {
        let revoked = checked("schema_version = 1\n[agent.claude-code]\nlifecycle = \"revoked\"\n");
        let approved =
            checked("schema_version = 1\n[agent.claude-code]\nlifecycle = \"approved\"\n");
        let none = AgentProfiles::default();
        let list: [LocalInstance; 0] = [];
        let code = |line: &str, merged: &AgentProfiles| {
            plan(
                &parse(&args(line)).unwrap(),
                &facts(&none, merged, &list, false),
                "m",
            )
            .err()
            .map(|r| r.code)
        };
        assert_eq!(code("approve claude-code", &revoked), Some("revoked"));
        assert_eq!(
            code("approve claude-code", &approved),
            Some("already_approved")
        );
        assert_eq!(code("revoke claude-code", &revoked), Some("revoked"));
        assert_eq!(
            code("profile claude-code general", &revoked),
            Some("revoked")
        );
        assert_eq!(
            code("profile claude-code eng", &none),
            Some("unknown_profile")
        );
        assert_eq!(
            code("approve claude-code --profile eng", &none),
            Some("unknown_profile")
        );
        assert_eq!(
            code(&format!("revoke claude-code --instance {ID}"), &none),
            Some("unknown_instance")
        );
        assert_eq!(code("revoke Claude", &none), Some("unknown_agent"));
        assert_eq!(code("approve claude-code", &none), None);
        let mut unknown = facts(&none, &none, &list, false);
        unknown.known_agent = false;
        assert_eq!(
            plan(&parse(&args("approve mystery")).unwrap(), &unknown, "m")
                .unwrap_err()
                .code,
            "unknown_agent"
        );
    }

    /// A change that lets the agent do more is confirmed by typing its name;
    /// a tightening, an approval with no profile and a revocation by `y`.
    #[test]
    fn a_relaxation_is_confirmed_by_typing_the_agent_name() {
        let general = AgentProfiles::default();
        let permissive = profiles::merge(
            Some(&checked(
                "schema_version = 1\n[profile.eng]\nallow_categories = [\"bare_ip_fetch\"]\n[agent.claude-code]\nprofile = \"eng\"\n",
            )),
            None,
        );
        let list = [instance(Trust::Confined, true)];
        let assign = parse(&args("profile claude-code eng --system")).unwrap();
        let widen = effect(
            &assign,
            &Edit::Assign("eng".into()),
            &general,
            &permissive,
            &list,
            "maria",
        );
        assert_eq!(widen.confirm, Confirm::TypedName);
        assert!(widen.relaxes);
        assert!(
            widen
                .before
                .contains("1 confined and 0 other instances today"),
            "{}",
            widen.before
        );
        assert_eq!(
            widen.done,
            "maria changed the claude-code profile from General rules to eng. Applies to 1 confined instance."
        );
        let back = effect(
            &parse(&args("profile claude-code general --system")).unwrap(),
            &Edit::Assign("general".into()),
            &permissive,
            &general,
            &list,
            "maria",
        );
        assert_eq!(back.confirm, Confirm::YesNo);
        let revoke = parse(&args("revoke claude-code")).unwrap();
        let e = effect(
            &revoke,
            &Edit::Revoke { instance: None },
            &general,
            &general,
            &[],
            "dev",
        );
        assert_eq!(e.confirm, Confirm::YesNo);
        assert_eq!(e.done, "dev revoked claude-code. Its history stays.");
        let allow = parse(&args("allow claude-code --category bare_ip_fetch --system")).unwrap();
        let e = effect(
            &allow,
            &Edit::Allow {
                rule: AllowRule::Category("bare_ip_fetch".into()),
                instance: None,
            },
            &general,
            &general,
            &[],
            "dev",
        );
        assert_eq!(
            e.confirm,
            Confirm::TypedName,
            "an allowance is always typed"
        );
        assert_eq!(
            e.done,
            "dev allowed bare_ip_fetch for claude-code (confined instances)."
        );
    }

    #[test]
    fn the_response_and_the_audit_line_say_the_same_thing() {
        let request = parse(&args(&format!("revoke claude-code --instance {ID}"))).unwrap();
        let refusal = refuse(
            "unknown_instance",
            "No instance 3f9a0c1e of claude-code was started here.",
        );
        let r = response(&request, Err(&refusal), None);
        assert_eq!(r["success"], false);
        assert_eq!(r["refused"], "unknown_instance");
        assert_eq!(r["skill_id"], "agent_revoke");
        assert!(r.get("second_factor").is_none());
        let line = audit_line(7, &request, "dev", None, "failure: unknown_instance", None);
        assert_eq!(line["kind"], "guard.agent_decision");
        assert_eq!(line["result"], "failure: unknown_instance");
        assert_eq!(line["instance_id"], ID);
        assert_eq!(line["file"], "user");
    }

    #[test]
    fn a_rows_identity_offers_what_its_state_allows() {
        let mut facts = DashboardFacts::default();
        let fresh = row_identity(&facts, "claude-code");
        assert_eq!(fresh.lifecycle, "discovered");
        assert_eq!(fresh.profile.label, "General rules");
        assert_eq!(fresh.profile.name, None);
        let commands: Vec<&str> = fresh
            .decision_steps
            .iter()
            .map(|s| s.command.as_str())
            .collect();
        assert_eq!(
            commands,
            [
                "innerwarden agents approve claude-code",
                "innerwarden agents revoke claude-code"
            ]
        );
        facts.profiles = profiles::merge(
            Some(&checked(
                "schema_version = 1\n[profile.eng]\nallow_categories = [\"bare_ip_fetch\"]\n[agent.claude-code]\nlifecycle = \"approved\"\nprofile = \"eng\"\n",
            )),
            None,
        );
        facts.instances = vec![instance(Trust::Confined, true), {
            let mut i = instance(Trust::Observed, true);
            i.instance_id = "other".into();
            i
        }];
        let approved = row_identity(&facts, "claude-code");
        assert_eq!(approved.lifecycle, "approved");
        assert_eq!(approved.profile.name.as_deref(), Some("eng"));
        assert_eq!(approved.profile.source, Some("system"));
        assert_eq!(
            (
                approved.profile.confined_instances,
                approved.profile.other_instances
            ),
            (1, 1)
        );
        let commands: Vec<&str> = approved
            .decision_steps
            .iter()
            .map(|s| s.command.as_str())
            .collect();
        assert_eq!(
            commands,
            [
                "sudo innerwarden agents profile claude-code general --system",
                "innerwarden agents revoke claude-code"
            ]
        );
        facts.profiles =
            checked("schema_version = 1\n[agent.claude-code]\nlifecycle = \"revoked\"\n");
        let revoked = row_identity(&facts, "claude-code");
        assert_eq!(revoked.lifecycle, "revoked");
        assert!(revoked.decision_steps.is_empty());
    }

    /// Who approved or revoked, when, and the owner come from the file as
    /// written; a type nobody decided about has none of them.
    #[test]
    fn a_rows_lifecycle_names_who_changed_it_and_the_owner() {
        let mut facts = DashboardFacts::default();
        let fresh = row_identity(&facts, "claude-code");
        assert_eq!(
            (fresh.lifecycle_by, fresh.lifecycle_at, fresh.owner),
            (None, None, None)
        );
        facts.profiles = checked(
            "schema_version = 1\n[agent.claude-code]\nlifecycle = \"approved\"\nowner = \"maria\"\napproved_by = \"dev\"\napproved_at = \"2026-10-16T09:00:00Z\"\n",
        );
        let approved = row_identity(&facts, "claude-code");
        assert_eq!(approved.lifecycle_by.as_deref(), Some("dev"));
        assert_eq!(
            approved.lifecycle_at.as_deref(),
            Some("2026-10-16T09:00:00Z")
        );
        assert_eq!(approved.owner.as_deref(), Some("maria"));
        facts.profiles = checked(
            "schema_version = 1\n[agent.claude-code]\nlifecycle = \"revoked\"\napproved_by = \"dev\"\nrevoked_by = \"ops\"\nrevoked_at = \"2026-10-17T10:00:00Z\"\n",
        );
        let revoked = row_identity(&facts, "claude-code");
        assert_eq!(revoked.lifecycle_by.as_deref(), Some("ops"));
        assert_eq!(
            revoked.lifecycle_at.as_deref(),
            Some("2026-10-17T10:00:00Z")
        );
    }
}
