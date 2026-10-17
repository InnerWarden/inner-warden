//! The per-agent profiles as the hook, the proxy and `contain` see them.
//!
//! The rules live in `innerwarden_agent_guard::profiles` (the file format, the
//! checks at load, the layers and their precedence). This module is the pure
//! glue between those rules and this binary: what the two files mean together,
//! how a hook verdict becomes the facts a decision is made from, what the
//! decision does to the verdict that is recorded, and what the audit line
//! says when the profiles change. The reads are in `agent_profiles_io`.
//!
//! With no profiles file on the host the state is [`ProfilesState::Off`] and
//! none of this is reached: the hook, the proxy and `contain` are what they
//! were.

use innerwarden_agent_guard::identity::{RuleLayer, Trust, Verdict};
use innerwarden_agent_guard::profiles::{
    self, AgentProfile, AgentProfiles, ProfileChange, ShellCall,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hook_identity::Identity;

/// One of the two files, as it was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileRead {
    /// Nothing at that path.
    Absent,
    /// A file that is the right owner's, and nobody else can write.
    Bytes(Vec<u8>),
    /// A file is there and is not one to trust or read, and why.
    Refused(String),
}

/// What the host's profiles amount to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfilesState {
    /// No profiles file at either place: everything is as it was.
    Off,
    /// The profiles in force.
    On(AgentProfiles),
    /// A file is there and cannot be used, and why, naming the file.
    Invalid(String),
}

/// PURE. The state two reads add up to. A file that cannot be used makes the
/// whole state invalid: a policy is never applied with half of it missing.
/// The user's file may only tighten (`profiles::check_user_file`).
pub fn state_from(system: (&str, FileRead), user: (&str, FileRead)) -> ProfilesState {
    let mut parsed = Vec::with_capacity(2);
    let mut any = false;
    for (index, (path, read)) in [system, user].into_iter().enumerate() {
        match read {
            FileRead::Absent => parsed.push(None),
            FileRead::Refused(why) => return ProfilesState::Invalid(format!("{path}: {why}")),
            FileRead::Bytes(bytes) => {
                any = true;
                let checked = profiles::parse(&bytes).and_then(|checked| {
                    if index == 1 {
                        profiles::check_user_file(&checked)?;
                    }
                    Ok(checked)
                });
                match checked {
                    Ok(checked) => parsed.push(Some(checked)),
                    Err(error) => return ProfilesState::Invalid(format!("{path}: {error}")),
                }
            }
        }
    }
    if !any {
        return ProfilesState::Off;
    }
    ProfilesState::On(profiles::merge(parsed[0].as_ref(), parsed[1].as_ref()))
}

/// The agent type whose profile a call gets: the one the hook line names,
/// else, for an instance whose own namespace matched its record, the one the
/// record names. With neither, none (the hard and general layers still hold).
pub fn agent_type(hook_agent: Option<&str>, identity: Option<&Identity>) -> Option<String> {
    hook_agent
        .map(str::to_string)
        .or_else(|| identity.and_then(|id| id.agent_type.clone()))
}

/// The trust a decision is made at: the hook's own reading of its instance,
/// `declared` with no record.
pub fn trust(identity: Option<&Identity>) -> Trust {
    identity.map(|id| id.trust).unwrap_or(Trust::Declared)
}

/// The signals a verdict CHARGED, the way the hook's own floor reads them: a
/// signal with no score counts, one scored 0 (a subsumed duplicate) does not.
pub fn charged_signals(verdict: &Value) -> Vec<String> {
    verdict
        .get("signals")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|signal| {
            signal
                .get("score")
                .and_then(Value::as_u64)
                .is_none_or(|score| score > 0)
        })
        .filter_map(|signal| signal.get("signal").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

/// The verdict word as a layer reads it, spelled as the hook reads it: what is
/// not `deny` or `review` is `allow`.
pub fn general_verdict(verdict: &Value) -> Verdict {
    match verdict.get("recommendation").and_then(Value::as_str) {
        Some("deny") => Verdict::Deny,
        Some("review") => Verdict::Review,
        _ => Verdict::Allow,
    }
}

/// What the hook does with one shell command when profiles are in force.
#[derive(Debug, Clone, PartialEq)]
pub struct HookDecision {
    /// The verdict to record and act on.
    pub verdict: Value,
    /// The hook refuses the command (outside monitor).
    pub blocks: bool,
    pub deciding_layer: RuleLayer,
    /// The profile in force for the caller's type, by name (`None`: the
    /// general rules).
    pub profile: Option<String>,
    /// The profile or the exception would have allowed it, the instance does
    /// not run confined, and the general rules decided.
    pub relaxation_withheld: bool,
}

/// The facts of one shell command, as the hook has them after the general
/// layer.
#[derive(Debug, Clone, Copy)]
pub struct HookFacts<'a> {
    pub command: &'a str,
    /// The verdict after the engine, the person's suppressions, the second
    /// opinion, the behaviour note and the tool-result check.
    pub verdict: &'a Value,
    /// What the hook would do with it before profiles (`hook_blocks`).
    pub blocks_today: bool,
    /// An argument came from an earlier tool result.
    pub tainted: bool,
    /// The hook line blocks on review.
    pub line_block_review: bool,
}

/// PURE. Decide one shell command with the layers, and write what they did
/// onto the verdict: the decision's word when it differs from the general
/// one, and a note in the explanation, the way a suppression is noted.
pub fn decide_hook(
    facts: &HookFacts<'_>,
    profiles: &AgentProfiles,
    agent_type: Option<&str>,
    instance_id: Option<&str>,
    trust: Trust,
) -> HookDecision {
    let charged = charged_signals(facts.verdict);
    let charged: Vec<&str> = charged.iter().map(String::as_str).collect();
    let general = general_verdict(facts.verdict);
    let call = ShellCall {
        general,
        charged: &charged,
        blocks_today: facts.blocks_today,
        names_llm_key: innerwarden_agent_guard::threats::names_guard_llm_key(facts.command),
        tainted: facts.tainted,
    };
    let named: Option<(&str, &AgentProfile)> =
        agent_type.and_then(|name| profiles.get(name).map(|profile| (name, profile)));
    let outcome = profiles::decide_shell_in(
        &call,
        named,
        profiles.facts(agent_type, instance_id),
        facts.line_block_review,
        trust,
    );
    let mut verdict = facts.verdict.clone();
    if let Some(obj) = verdict.as_object_mut() {
        if outcome.decision.verdict != general {
            obj.insert(
                "recommendation".into(),
                json!(profiles::recommendation(&outcome.decision)),
            );
        }
        if let Some(note) = &outcome.note {
            let base = obj
                .get("explanation")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            obj.insert(
                "explanation".into(),
                json!(format!("{base} [{note}]").trim()),
            );
        }
    }
    HookDecision {
        verdict,
        blocks: outcome.blocks,
        deciding_layer: outcome.decision.deciding_layer,
        profile: agent_type.and_then(|name| crate::agent_decisions::profile_name(profiles, name)),
        relaxation_withheld: outcome.relaxation_withheld,
    }
}

// ---------------------------------------------------------------------------
// The audit line
// ---------------------------------------------------------------------------

/// What the last process to load the profiles saw, kept beside the record so
/// the next one can say what changed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// The last profiles that were in force.
    pub profiles: AgentProfiles,
    /// The reason the file was last refused, while it is.
    pub rejected: Option<String>,
}

/// PURE. What to write when `state` follows `previous` (the snapshot's bytes,
/// `None` when there is none, garbage read as none): the new snapshot and the
/// changes to report, or `None` when nothing changed. `Off` reports nothing:
/// with no file on the host, nothing new is read or written.
pub fn audit_step(
    previous: Option<&[u8]>,
    state: &ProfilesState,
) -> Option<(Vec<u8>, Vec<ProfileChange>)> {
    let before: Snapshot = previous
        .and_then(|bytes| serde_json::from_slice(bytes).ok())
        .unwrap_or_default();
    let (after, changes) = match state {
        ProfilesState::Off => return None,
        ProfilesState::On(current) => {
            let mut changes = profiles::changes(&before.profiles, current);
            if before.rejected.is_some() {
                changes.insert(0, ProfileChange::to_type("profiles_accepted", "", ""));
            }
            (
                Snapshot {
                    profiles: current.clone(),
                    rejected: None,
                },
                changes,
            )
        }
        ProfilesState::Invalid(why) => {
            if before.rejected.as_deref() == Some(why.as_str()) {
                return None;
            }
            (
                Snapshot {
                    profiles: before.profiles.clone(),
                    rejected: Some(why.clone()),
                },
                vec![ProfileChange::to_type("profiles_rejected", "", why)],
            )
        }
    };
    if changes.is_empty() && previous.is_some() && after == before {
        return None;
    }
    let bytes = serde_json::to_vec(&after).ok()?;
    Some((bytes, changes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_agent_guard::identity::Reason;

    const STRICT: &str =
        "schema_version = 1\n[profile.claude-code]\ndeny_categories = [\"bare_ip_fetch\"]\n";
    const PERMISSIVE: &str =
        "schema_version = 1\n[profile.claude-code]\nallow_categories = [\"bare_ip_fetch\"]\n";

    fn on(text: &str) -> AgentProfiles {
        match state_from(
            ("/etc/x", FileRead::Bytes(text.as_bytes().to_vec())),
            ("~/x", FileRead::Absent),
        ) {
            ProfilesState::On(p) => p,
            other => panic!("{other:?}"),
        }
    }

    fn identity(trust: Trust) -> Identity {
        Identity {
            instance_id: (trust > Trust::Declared).then(|| "7f3a9c1e-42".into()),
            session_id: None,
            trust,
            reason: Reason::ConfinedByNamespace,
            agent_type: (trust > Trust::Declared).then(|| "claude-code".into()),
        }
    }

    fn review(signal: &str) -> Value {
        json!({
            "recommendation": "review",
            "risk_score": 25,
            "explanation": "fetch from a bare IP",
            "signals": [{"signal": signal, "score": 25, "detail": "x"}],
        })
    }

    #[test]
    fn no_file_at_either_place_is_off() {
        assert_eq!(
            state_from(("/etc/x", FileRead::Absent), ("~/x", FileRead::Absent)),
            ProfilesState::Off
        );
    }

    /// One file that cannot be used invalidates the state, naming the file:
    /// the other file's rules are not applied without it.
    #[test]
    fn one_bad_file_makes_the_state_invalid_and_names_it() {
        let bad = state_from(
            ("/etc/x", FileRead::Bytes(STRICT.as_bytes().to_vec())),
            (
                "/home/u/x",
                FileRead::Bytes(
                    b"schema_version = 1\n[profile.claude-code]\ndeny_categories = [\"nope\"]\n"
                        .to_vec(),
                ),
            ),
        );
        let ProfilesState::Invalid(why) = bad else {
            panic!("{bad:?}")
        };
        assert!(why.starts_with("/home/u/x: "), "{why}");
        assert!(why.contains("`nope` is not a signal name"), "{why}");
        let refused = state_from(
            (
                "/etc/x",
                FileRead::Refused("is writable by its group".into()),
            ),
            ("~/x", FileRead::Bytes(PERMISSIVE.as_bytes().to_vec())),
        );
        assert_eq!(
            refused,
            ProfilesState::Invalid("/etc/x: is writable by its group".into())
        );
        // The user's file may not relax; the same text in the system file may.
        let relaxing = || FileRead::Bytes(PERMISSIVE.as_bytes().to_vec());
        assert!(matches!(
            state_from(("/etc/x", FileRead::Absent), ("/home/u/x", relaxing())),
            ProfilesState::Invalid(ref why) if why.starts_with("/home/u/x: ") && why.contains("may relax")
        ));
        assert!(matches!(
            state_from(("/etc/x", relaxing()), ("/home/u/x", FileRead::Absent)),
            ProfilesState::On(_)
        ));
        // An empty file is a file: refused for having no schema.
        assert!(matches!(
            state_from(
                ("/etc/x", FileRead::Bytes(vec![])),
                ("~/x", FileRead::Absent)
            ),
            ProfilesState::Invalid(_)
        ));
    }

    #[test]
    fn the_type_comes_from_the_hook_line_else_a_matched_record() {
        assert_eq!(agent_type(Some("cursor"), None).as_deref(), Some("cursor"));
        assert_eq!(
            agent_type(None, Some(&identity(Trust::Confined))).as_deref(),
            Some("claude-code")
        );
        assert_eq!(agent_type(None, Some(&identity(Trust::Declared))), None);
        assert_eq!(agent_type(None, None), None);
        assert_eq!(trust(None), Trust::Declared);
        assert_eq!(trust(Some(&identity(Trust::Observed))), Trust::Observed);
    }

    #[test]
    fn charged_signals_read_like_the_hook_floor() {
        let verdict = json!({"signals": [
            {"signal": "a", "score": 10},
            {"signal": "b", "score": 0},
            {"signal": "c"},
        ]});
        assert_eq!(charged_signals(&verdict), ["a", "c"]);
        assert_eq!(
            general_verdict(&json!({"recommendation": "odd"})),
            Verdict::Allow
        );
    }

    /// The test the spec names: a declared agent that calls itself the
    /// permissive type gets the general policy. Through this module, from a
    /// real verdict and a real file.
    ///
    /// FAILS ON REVERT: relax for `Observed` in `identity::decide` and the
    /// observed row is let through.
    #[test]
    fn a_declared_or_observed_agent_named_as_the_permissive_type_gets_the_general_policy() {
        let profiles = on(PERMISSIVE);
        let verdict = review("bare_ip_fetch");
        let facts = HookFacts {
            command: "curl http://203.0.113.9/x",
            verdict: &verdict,
            blocks_today: true,
            tainted: false,
            line_block_review: true,
        };
        for trust in [Trust::Declared, Trust::Observed] {
            let out = decide_hook(&facts, &profiles, Some("claude-code"), None, trust);
            assert!(out.blocks, "{trust:?}");
            assert_eq!(out.deciding_layer, RuleLayer::General);
            assert_eq!(out.verdict, verdict, "the verdict is not touched");
            assert!(out.relaxation_withheld, "{trust:?}");
            assert_eq!(out.profile.as_deref(), Some("claude-code"));
        }
        let out = decide_hook(
            &facts,
            &profiles,
            Some("claude-code"),
            None,
            Trust::Confined,
        );
        assert!(!out.blocks);
        assert_eq!(out.deciding_layer, RuleLayer::AgentType);
        assert!(!out.relaxation_withheld);
        assert_eq!(out.verdict["recommendation"], "allow");
        assert!(out.verdict["explanation"].as_str().unwrap().ends_with(
            "[the `claude-code` agent profile allows bare_ip_fetch for this confined instance]"
        ));
    }

    /// The hook's own reading of the jail it runs in, with every fact
    /// matching (the same facts a record the agent made for itself, in a
    /// namespace of its own, would give), is decided at a level that unlocks
    /// no relaxation: the profile's allow and an exception for the instance
    /// are withheld and the general review stands.
    ///
    /// FAILS ON REVERT: return `confined` from row 10 of
    /// `identity::judge_trust_in_jail` and the call is let through by the
    /// exception.
    #[test]
    fn the_hooks_own_reading_of_its_jail_unlocks_no_relaxation() {
        const NS: u64 = 4026533001;
        const MNT: u64 = 4026533002;
        const ID: &str = "3f9a0c1e5b7d42a8c6e1f0b2d4a69c87";
        let record = format!(
            r#"{{"schema":1,"instance_id":"{ID}","agent_type":"claude-code","launcher":{{"path":"/usr/local/bin/innerwarden","version":"1","root_owned":true}},"uid":1000,"project":"p","mode":"enforce","started_at":"2026-10-16T09:30:00Z","jail":{{"backend":"bwrap","pid":1,"start_ticks":1,"pid_ns":{NS},"mnt_ns":{MNT}}},"scope":{{"user":{{"unit":"innerwarden-contain-{ID}.scope","cgroup_path":"/user.slice/user-1000.slice/user@1000.service/app.slice/innerwarden-contain-{ID}.scope"}}}}}}"#
        );
        let read = crate::hook_identity::resolve(
            &crate::hook_identity::JailFacts {
                record: crate::hook_identity::RawRecord::Bytes {
                    bytes: record.into_bytes(),
                    read_only: true,
                },
                own_pid_ns: Some(NS),
                own_mnt_ns: Some(MNT),
                launcher_agent: Some("claude-code".into()),
            },
            None,
            None,
        )
        .expect("a record was there");
        assert_eq!(read.instance_id.as_deref(), Some(ID));
        assert_eq!(read.reason, Reason::ConfinedByNamespace);
        let profiles = on(&format!(
            "{PERMISSIVE}[[agent.claude-code.exception]]\ninstance_id = \"{ID}\"\ncategory = \"bare_ip_fetch\"\n"
        ));
        let verdict = review("bare_ip_fetch");
        let facts = HookFacts {
            command: "curl http://203.0.113.9/x",
            verdict: &verdict,
            blocks_today: true,
            tainted: false,
            line_block_review: true,
        };
        let out = decide_hook(
            &facts,
            &profiles,
            agent_type(None, Some(&read)).as_deref(),
            read.instance_id.as_deref(),
            trust(Some(&read)),
        );
        assert!(out.blocks);
        assert_eq!(out.deciding_layer, RuleLayer::General);
        assert_eq!(out.verdict, verdict, "the verdict is not touched");
        assert!(out.relaxation_withheld);
    }

    #[test]
    fn a_profile_deny_is_written_onto_the_verdict() {
        let profiles = on(STRICT);
        let verdict = review("bare_ip_fetch");
        let facts = HookFacts {
            command: "curl http://203.0.113.9/x",
            verdict: &verdict,
            blocks_today: false,
            tainted: false,
            line_block_review: false,
        };
        let out = decide_hook(
            &facts,
            &profiles,
            Some("claude-code"),
            None,
            Trust::Declared,
        );
        assert!(out.blocks);
        assert_eq!(out.deciding_layer, RuleLayer::AgentType);
        assert_eq!(out.verdict["recommendation"], "deny");
        assert!(out.verdict["explanation"]
            .as_str()
            .unwrap()
            .contains("denies bare_ip_fetch"));
        // Another type has no profile: the general layer, untouched.
        let other = decide_hook(&facts, &profiles, Some("cursor"), None, Trust::Declared);
        assert!(!other.blocks);
        assert_eq!(other.verdict, verdict);
        assert_eq!(other.profile, None);
        assert!(!other.relaxation_withheld);
    }

    #[test]
    fn reaching_the_llm_key_is_refused_for_every_type() {
        let profiles = on(PERMISSIVE);
        let verdict =
            json!({"recommendation": "allow", "risk_score": 0, "explanation": "", "signals": []});
        let facts = HookFacts {
            command: "cat ~/.config/innerwarden/llm-key",
            verdict: &verdict,
            blocks_today: false,
            tainted: false,
            line_block_review: false,
        };
        for agent in [Some("claude-code"), Some("cursor"), None] {
            let out = decide_hook(&facts, &profiles, agent, None, Trust::Confined);
            assert!(out.blocks, "{agent:?}");
            assert_eq!(out.deciding_layer, RuleLayer::Hard);
            assert_eq!(out.verdict["recommendation"], "deny");
        }
    }

    // -- the audit -----------------------------------------------------------

    fn actions(step: &(Vec<u8>, Vec<ProfileChange>)) -> Vec<String> {
        step.1
            .iter()
            .map(|c| format!("{} {} {}", c.action, c.agent_type, c.value))
            .collect()
    }

    #[test]
    fn the_audit_reports_a_change_once_and_nothing_when_off_or_unchanged() {
        let first = audit_step(None, &ProfilesState::On(on(STRICT))).unwrap();
        assert_eq!(
            actions(&first),
            [
                "profile_added claude-code ",
                "deny_category_added claude-code bare_ip_fetch"
            ]
        );
        assert_eq!(
            audit_step(Some(&first.0), &ProfilesState::On(on(STRICT))),
            None
        );
        assert_eq!(audit_step(Some(&first.0), &ProfilesState::Off), None);
        assert_eq!(audit_step(None, &ProfilesState::Off), None);

        let next = audit_step(Some(&first.0), &ProfilesState::On(on(PERMISSIVE))).unwrap();
        assert_eq!(
            actions(&next),
            [
                "allow_category_added claude-code bare_ip_fetch",
                "deny_category_removed claude-code bare_ip_fetch"
            ]
        );

        let rejected =
            audit_step(Some(&next.0), &ProfilesState::Invalid("/etc/x: bad".into())).unwrap();
        assert_eq!(actions(&rejected), ["profiles_rejected  /etc/x: bad"]);
        assert_eq!(
            audit_step(
                Some(&rejected.0),
                &ProfilesState::Invalid("/etc/x: bad".into())
            ),
            None,
            "the same refusal is reported once"
        );
        // Fixed again: accepted, and only what differs from the last profiles
        // in force is reported.
        let fixed = audit_step(Some(&rejected.0), &ProfilesState::On(on(PERMISSIVE))).unwrap();
        assert_eq!(actions(&fixed), ["profiles_accepted  "]);
        // A snapshot that is not one is read as none.
        let garbage = audit_step(Some(b"not json"), &ProfilesState::On(on(STRICT))).unwrap();
        assert_eq!(garbage.1.len(), 2);
    }
}
