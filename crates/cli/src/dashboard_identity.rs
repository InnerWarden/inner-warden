//! The identity fields of the local dashboard's `GET /api/agents`: how far
//! each agent's own word is backed, the instances a launcher started for this
//! user, and the one step that would back it further.
//!
//! PURE: everything is read by the caller (the launcher's records, what the
//! dashboard saw of each jail, the labels the hook left in the record) and
//! this module only words and orders it. Nothing here is a decision: the hook
//! decides, inside the jail, every time. What this module serves is a LABEL
//! for a person, and it is never shown above what its own evidence supports:
//!
//! * an instance with no label from its hook yet is `declared`, "not checked
//!   yet", whatever its record says;
//! * a label is capped by the trust its reason can support, so a label that
//!   pairs `confined` with a reason that proves nothing reads as `declared`;
//! * for a jail that still runs, the label is capped by what the dashboard
//!   itself reads of that jail (the record against the jail's namespaces),
//!   so a forged label in the record cannot raise a live instance;
//! * nothing this dashboard reads is a witness from outside the jail (the
//!   hook's label, the launcher's record and the jail's namespaces are all
//!   facts the agent's own process can produce), so no instance is ever
//!   served above `observed`: `host_verified` is only for a witness outside
//!   the agent, which the Community dashboard is not.

use std::collections::BTreeMap;

use innerwarden_agent_guard::identity::{LaunchMode, LaunchRecord, Reason, Trust};
use innerwarden_graph::InstanceActivity;
use serde::Serialize;

use crate::agent_decisions::DecisionStep;
use crate::dashboard_community::{reveal_hidden, rfc3339};

/// Most instances one agent row lists; the rest are counted.
pub const MAX_INSTANCES: usize = 20;
/// Most sessions one instance lists.
pub const MAX_SESSIONS: usize = 5;
/// How many characters of a session id the page shows.
const SESSION_LABEL_CHARS: usize = 8;

/// The reason of an instance whose hook has not reported since it started.
pub const NOT_CHECKED_YET: &str = "not_checked_yet";
/// The reason of an agent with no live instance in a jail.
pub const NO_INSTANCE: &str = "no_instance";

/// One instance as the dashboard read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceFacts {
    pub record: LaunchRecord,
    /// The jail process still runs: its pid AND its start time match.
    pub live: bool,
    /// For a live jail, what the hook inside it would judge from the record
    /// and the jail's own namespaces. `None` once the jail has ended.
    pub judged: Option<(Trust, Reason)>,
    /// The account name of the record's uid, `None` when it does not resolve.
    pub user: Option<String>,
}

/// The wire word for a trust level (spec 104 D1): one vocabulary on every
/// screen.
pub fn wire_trust(trust: Trust) -> &'static str {
    match trust {
        Trust::Confined => "host_verified",
        Trust::Observed => "observed",
        Trust::Declared => "declared",
    }
}

fn trust_word(word: &str) -> Option<Trust> {
    match word {
        "confined" => Some(Trust::Confined),
        "observed" => Some(Trust::Observed),
        "declared" => Some(Trust::Declared),
        _ => None,
    }
}

/// The most a reason code can support. A code this build does not know
/// supports nothing above `declared`, and none supports more than
/// `observed`: every code here is a reading from inside the jail, and a
/// reading from inside the jail tops at `observed` (`judge_trust_in_jail`,
/// row 10), `confined_by_namespace` included.
pub fn reason_ceiling(reason: &str) -> Trust {
    match reason {
        "confined_by_namespace" | "launcher_not_trusted" | "no_scope" => Trust::Observed,
        _ => Trust::Declared,
    }
}

/// A hook label as recorded (`confined`, `confined_by_namespace`), capped by
/// what its reason supports. `None` for a word that is not a trust word.
pub fn capped_label(trust: &str, reason: Option<&str>) -> Option<Trust> {
    let claimed = trust_word(trust)?;
    Some(claimed.min(reason_ceiling(reason.unwrap_or(""))))
}

/// The trust and reason one instance is shown at. See the module doc.
pub fn instance_trust(
    facts: &InstanceFacts,
    activity: Option<&InstanceActivity>,
) -> (Trust, String) {
    let label = activity.and_then(|a| {
        let reason = a.trust_reason.clone().unwrap_or_default();
        capped_label(a.trust.as_deref()?, Some(&reason)).map(|trust| (trust, reason))
    });
    let Some((trust, reason)) = label else {
        return (Trust::Declared, NOT_CHECKED_YET.to_string());
    };
    match facts.judged {
        Some((seen, why)) if seen < trust => (seen, why.as_str().to_string()),
        _ => (trust, reason),
    }
}

fn mode_word(mode: LaunchMode) -> &'static str {
    match mode {
        LaunchMode::Monitor => "monitor",
        LaunchMode::Enforce => "enforce",
        LaunchMode::BlockReview => "block-review",
    }
}

fn shown(text: &str) -> String {
    reveal_hidden(text).0
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionView {
    /// The first characters of the session id the agent put in its payload.
    pub session: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_at: Option<String>,
    /// The newest decision of the session the guard flagged, or `null`.
    pub case_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TechnicalView {
    pub jail_pid: u32,
    pub jail_start_ticks: u64,
    pub pid_ns: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_unit: Option<String>,
    pub launcher_path: String,
    pub launcher_root_owned: bool,
}

/// One instance, as `/api/agents` lists it under its agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalInstanceView {
    pub instance_id: String,
    pub trust: &'static str,
    pub trust_reason: String,
    pub trust_source: &'static str,
    pub user: Option<String>,
    pub uid: u32,
    pub project: String,
    pub mode: &'static str,
    pub started_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_activity_at: Option<String>,
    pub live: bool,
    pub sessions: Vec<SessionView>,
    pub technical: TechnicalView,
}

fn started_ms(record: &LaunchRecord) -> u64 {
    u64::try_from(record.started_at.timestamp_millis()).unwrap_or(0)
}

/// PURE. One instance's view.
pub fn instance_view(
    facts: &InstanceFacts,
    activity: Option<&InstanceActivity>,
) -> LocalInstanceView {
    let record = &facts.record;
    let (trust, trust_reason) = instance_trust(facts, activity);
    let sessions = activity
        .map(|a| {
            a.sessions
                .iter()
                .take(MAX_SESSIONS)
                .map(|s| SessionView {
                    session: shown(&s.session_id)
                        .chars()
                        .take(SESSION_LABEL_CHARS)
                        .collect(),
                    first_at: s.first_at_ms.map(rfc3339),
                    last_at: s.last_at_ms.map(rfc3339),
                    case_id: s.case_id.clone(),
                })
                .collect()
        })
        .unwrap_or_default();
    let scope_unit = record
        .scope
        .as_ref()
        .and_then(|s| s.system.as_ref().or(s.user.as_ref()))
        .map(|scope| shown(&scope.unit));
    LocalInstanceView {
        instance_id: record.instance_id.clone(),
        trust: wire_trust(trust),
        trust_reason,
        trust_source: "jail",
        user: facts.user.as_deref().map(shown),
        uid: record.uid,
        project: shown(&record.project),
        mode: mode_word(record.mode),
        started_at: rfc3339(started_ms(record)),
        last_activity_at: activity.and_then(|a| a.last_at_ms).map(rfc3339),
        live: facts.live,
        sessions,
        technical: TechnicalView {
            jail_pid: record.jail.pid,
            jail_start_ticks: record.jail.start_ticks,
            pid_ns: record.jail.pid_ns,
            scope_unit,
            launcher_path: shown(&record.launcher.path),
            launcher_root_owned: record.launcher.root_owned,
        },
    }
}

/// The trust fields of one agent row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowTrust {
    pub trust: &'static str,
    pub trust_reason: String,
    pub confine_step: Option<DecisionStep>,
    pub instances: Vec<LocalInstanceView>,
    /// Instances of this agent not listed.
    pub more_instances: usize,
}

/// PURE. The trust fields for agent `id`: its instances (live first, then
/// the most recent), the worst trust among the live ones (`declared`,
/// `no_instance` with none), and the step for that reason.
pub fn row_trust(
    id: &str,
    records: &[InstanceFacts],
    activity: &BTreeMap<String, InstanceActivity>,
    linux: bool,
) -> RowTrust {
    let mut mine: Vec<&InstanceFacts> = records
        .iter()
        .filter(|facts| facts.record.agent_type == id)
        .collect();
    mine.sort_by(|a, b| {
        b.live
            .cmp(&a.live)
            .then_with(|| b.record.started_at.cmp(&a.record.started_at))
            .then_with(|| a.record.instance_id.cmp(&b.record.instance_id))
    });
    let mut worst: Option<(Trust, String)> = None;
    for facts in mine.iter().filter(|facts| facts.live) {
        let (trust, reason) = instance_trust(facts, activity.get(&facts.record.instance_id));
        if worst.as_ref().is_none_or(|(seen, _)| trust < *seen) {
            worst = Some((trust, reason));
        }
    }
    let (trust, trust_reason) = worst.unwrap_or((Trust::Declared, NO_INSTANCE.to_string()));
    let more_instances = mine.len().saturating_sub(MAX_INSTANCES);
    RowTrust {
        trust: wire_trust(trust),
        confine_step: confine_step(id, &trust_reason, linux),
        trust_reason,
        instances: mine
            .into_iter()
            .take(MAX_INSTANCES)
            .map(|facts| instance_view(facts, activity.get(&facts.record.instance_id)))
            .collect(),
        more_instances,
    }
}

/// The command each agent type is launched by, where one is known, and the
/// line that goes with it. A type not listed gets no command: the page never
/// shows one that was guessed.
const LAUNCH_COMMANDS: &[(&str, &str, &str)] = &[(
    "claude-code",
    "claude",
    "Runs Claude Code in a jail it cannot leave, so its own word is no longer the only proof. \
     To make it the default, add alias claude='innerwarden contain --identity -- claude' to \
     your shell.",
)];

/// PURE. The step that would back an agent further, for the reason its
/// worst live instance has (spec 104 P2), or `None` when there is none to
/// print: a confined jail, a reason that a command does not fix (a backend
/// with no process namespace, a jail with no scope, a jail not checked yet),
/// a type whose launch command is not known, or a platform where a jail
/// cannot be checked from inside (only Linux has the process namespace).
pub fn confine_step(id: &str, reason: &str, linux: bool) -> Option<DecisionStep> {
    match reason {
        "launcher_not_trusted" => Some(DecisionStep {
            label: "Install InnerWarden system-wide",
            command: "sudo npm install -g innerwarden".to_string(),
            line: "Root then owns the launcher, so no program you run can replace it. Remove the \
                   copy in ~/.local/bin so your shell finds the system one, and start the agent \
                   again.",
        }),
        "no_instance"
        | "no_record"
        | "record_unreadable"
        | "record_writable"
        | "host_namespace_recorded"
        | "own_namespace_unreadable"
        | "namespace_mismatch"
        | "own_mount_namespace_unreadable"
        | "mount_namespace_mismatch"
        | "agent_mismatch"
        | "agent_not_named"
            if linux =>
        {
            let (_, program, line) = LAUNCH_COMMANDS.iter().find(|(agent, _, _)| *agent == id)?;
            Some(DecisionStep {
                label: "Start it in a jail",
                command: format!("innerwarden contain --identity -- {program}"),
                line,
            })
        }
        _ => None,
    }
}

/// The longest problem text served about the profiles file.
const PROBLEM_MAX_CHARS: usize = 400;

/// What the page says when a profiles file is there and cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProfilesFileView {
    pub state: &'static str,
    pub sentence: String,
}

/// PURE. The state of an unusable profiles file, in the words the page
/// prints: never silence, because the hook refuses every call while it is.
pub fn profiles_file_view(problem: &str) -> ProfilesFileView {
    let problem: String = shown(problem)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(PROBLEM_MAX_CHARS)
        .collect();
    ProfilesFileView {
        state: "invalid",
        sentence: format!(
            "The agent profiles file cannot be used ({problem}). Until it is fixed or removed, \
             a guard that refuses refuses every call of its agent instead of screening it \
             against rules that are not the ones written, and monitor mode screens with your \
             general rules. What was decided about each agent cannot be shown until then."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_agent_guard::identity::parse_launch_record;
    use innerwarden_graph::InstanceSession;

    const ID: &str = "3f9a0c1e5b7d42a8c6e1f0b2d4a69c87";
    const OTHER: &str = "0000000000000000000000000000beef";

    fn record(id: &str, agent: &str, root_owned: bool, started: &str) -> LaunchRecord {
        parse_launch_record(
            format!(
                r#"{{"schema":1,"instance_id":"{id}","agent_type":"{agent}","launcher":{{"path":"/usr/local/bin/innerwarden","version":"1.6.0","root_owned":{root_owned}}},"uid":1000,"project":"payments-api","mode":"enforce","started_at":"{started}","jail":{{"backend":"bwrap","pid":2778,"start_ticks":1234567,"pid_ns":4026532220,"mnt_ns":4026532218}},"scope":{{"user":{{"unit":"innerwarden-contain-{id}.scope","cgroup_path":"/user.slice/user-1000.slice/user@1000.service/app.slice/innerwarden-contain-{id}.scope"}}}}}}"#
            )
            .as_bytes(),
        )
        .expect("record")
    }

    fn facts(id: &str, live: bool, judged: Option<(Trust, Reason)>) -> InstanceFacts {
        InstanceFacts {
            record: record(id, "claude-code", true, "2026-10-16T09:12:03Z"),
            live,
            judged,
            user: Some("dev".into()),
        }
    }

    fn label(trust: &str, reason: &str) -> InstanceActivity {
        InstanceActivity {
            trust: Some(trust.into()),
            trust_reason: Some(reason.into()),
            last_at_ms: Some(1_760_607_651_000),
            sessions: vec![InstanceSession {
                session_id: "a1b2c3d4e5f6-session".into(),
                first_at_ms: Some(1_760_605_930_000),
                last_at_ms: Some(1_760_607_651_000),
                case_id: Some("cmd:contain:3".into()),
            }],
        }
    }

    /// Nothing the Community dashboard reads is a witness from outside the
    /// jail, so no instance and no row is ever served as `host_verified`:
    /// not a live one, not an ENDED one whose label in the agent-writable
    /// project graph says `confined`, whatever reason it pairs that with.
    ///
    /// FAILS ON REVERT: map `confined_by_namespace` to `Confined` in
    /// `reason_ceiling` again and the ended instance labelled
    /// `confined`/`confined_by_namespace` is served as `host_verified`.
    #[test]
    fn the_community_dashboard_never_serves_host_verified() {
        let mut reasons: Vec<&str> = [
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
        ]
        .iter()
        .map(|r| r.as_str())
        .collect();
        reasons.extend(["sensor_confirmed", "host_verified", "", "made_up"]);
        for reason in reasons {
            assert!(reason_ceiling(reason) <= Trust::Observed, "{reason}");
            for live in [false, true] {
                let judged = live.then_some((Trust::Observed, Reason::ConfinedByNamespace));
                let view =
                    instance_view(&facts(ID, live, judged), Some(&label("confined", reason)));
                assert_ne!(view.trust, "host_verified", "{reason} live={live}");
                let mut activity = BTreeMap::new();
                activity.insert(ID.to_string(), label("confined", reason));
                let row = row_trust("claude-code", &[facts(ID, live, judged)], &activity, true);
                assert_ne!(row.trust, "host_verified", "{reason} live={live}");
            }
        }
        let ended = instance_view(
            &facts(ID, false, None),
            Some(&label("confined", "confined_by_namespace")),
        );
        assert_eq!(
            (ended.trust, ended.trust_reason.as_str()),
            ("observed", "confined_by_namespace")
        );
    }

    #[test]
    fn the_wire_words_are_the_closed_table() {
        assert_eq!(wire_trust(Trust::Confined), "host_verified");
        assert_eq!(wire_trust(Trust::Observed), "observed");
        assert_eq!(wire_trust(Trust::Declared), "declared");
    }

    /// An instance the hook has not reported on is never above `declared`,
    /// whatever its record says.
    ///
    /// FAILS ON REVERT: return the dashboard's own judgment when no label
    /// exists and the live instance whose reading held reads `observed`.
    #[test]
    fn an_instance_with_no_label_is_not_checked_yet() {
        let live = facts(
            ID,
            true,
            Some((Trust::Observed, Reason::ConfinedByNamespace)),
        );
        assert_eq!(
            instance_trust(&live, None),
            (Trust::Declared, NOT_CHECKED_YET.to_string())
        );
        let unlabelled = InstanceActivity {
            trust: None,
            ..label("confined", "confined_by_namespace")
        };
        assert_eq!(instance_trust(&live, Some(&unlabelled)).0, Trust::Declared);
    }

    /// A label is capped by its reason, and a live jail's label by what the
    /// dashboard reads of that jail: a forged `confined` never raises it.
    ///
    /// FAILS ON REVERT: drop the `seen < trust` cap and the live jail whose
    /// namespace does not match its record reads `confined`.
    #[test]
    fn a_label_never_reads_above_its_reason_or_the_live_jail() {
        let live_mismatch = facts(ID, true, Some((Trust::Declared, Reason::NamespaceMismatch)));
        assert_eq!(
            instance_trust(
                &live_mismatch,
                Some(&label("confined", "confined_by_namespace"))
            ),
            (Trust::Declared, "namespace_mismatch".to_string())
        );
        let live_ok = facts(
            ID,
            true,
            Some((Trust::Observed, Reason::ConfinedByNamespace)),
        );
        assert_eq!(
            instance_trust(&live_ok, Some(&label("confined", "no_record"))).0,
            Trust::Declared,
            "a reason that proves nothing caps the label"
        );
        assert_eq!(
            instance_trust(&live_ok, Some(&label("confined", "confined_by_namespace"))),
            (Trust::Observed, "confined_by_namespace".to_string())
        );
        assert_eq!(
            instance_trust(&live_ok, Some(&label("observed", "launcher_not_trusted"))).0,
            Trust::Observed,
            "the label is never raised by the dashboard's own reading"
        );
        // An ended jail keeps the label it had, capped by its reason.
        let ended = facts(ID, false, None);
        assert_eq!(
            instance_trust(&ended, Some(&label("confined", "confined_by_namespace"))).0,
            Trust::Observed
        );
        assert_eq!(
            instance_trust(&ended, Some(&label("root", "confined_by_namespace"))).0,
            Trust::Declared
        );
    }

    /// The row takes the worst LIVE instance; with none live it is
    /// `declared`, `no_instance`. Live instances are listed first, then the
    /// newest, at most twenty, and the rest are counted.
    #[test]
    fn the_row_is_its_worst_live_instance() {
        let mut records = vec![
            facts(
                ID,
                true,
                Some((Trust::Observed, Reason::ConfinedByNamespace)),
            ),
            facts(
                OTHER,
                true,
                Some((Trust::Observed, Reason::LauncherNotTrusted)),
            ),
        ];
        records.push(InstanceFacts {
            record: record(
                "1111111111111111111111111111aaaa",
                "claude-code",
                true,
                "2026-10-17T09:00:00Z",
            ),
            live: false,
            judged: None,
            user: None,
        });
        let mut activity = BTreeMap::new();
        activity.insert(ID.to_string(), label("confined", "confined_by_namespace"));
        activity.insert(OTHER.to_string(), label("observed", "launcher_not_trusted"));
        let row = row_trust("claude-code", &records, &activity, true);
        assert_eq!(row.trust, "observed");
        assert_eq!(row.trust_reason, "launcher_not_trusted");
        assert_eq!(
            row.confine_step.as_ref().map(|s| s.command.as_str()),
            Some("sudo npm install -g innerwarden")
        );
        let ids: Vec<&str> = row
            .instances
            .iter()
            .map(|i| i.instance_id.as_str())
            .collect();
        assert_eq!(
            ids[2], "1111111111111111111111111111aaaa",
            "ended last: {ids:?}"
        );
        assert_eq!(row.more_instances, 0);
        let none = row_trust("cursor", &records, &activity, true);
        assert_eq!(
            (none.trust, none.trust_reason.as_str()),
            ("declared", NO_INSTANCE)
        );
        assert!(none.instances.is_empty());
        assert_eq!(
            none.confine_step, None,
            "no launch command is known for cursor"
        );
        let many: Vec<InstanceFacts> = (0..23)
            .map(|n| InstanceFacts {
                record: record(
                    &format!("{n:032x}"),
                    "claude-code",
                    true,
                    "2026-10-16T09:12:03Z",
                ),
                live: false,
                judged: None,
                user: None,
            })
            .collect();
        let row = row_trust("claude-code", &many, &BTreeMap::new(), true);
        assert_eq!(row.instances.len(), MAX_INSTANCES);
        assert_eq!(row.more_instances, 3);
        assert_eq!(row.trust_reason, NO_INSTANCE);
    }

    /// Every step printed is one the CLI accepts, and none is printed where
    /// a command does not fix the reason, for an unknown type, or off Linux.
    #[test]
    fn the_confine_step_is_a_command_the_cli_accepts() {
        let step = confine_step("claude-code", NO_INSTANCE, true).expect("S1");
        assert_eq!(step.command, "innerwarden contain --identity -- claude");
        let argv: Vec<String> = step
            .command
            .split_whitespace()
            .skip(2)
            .map(str::to_string)
            .collect();
        let parsed = crate::contain::parse_contain_args(&argv).expect("contain accepts it");
        assert!(parsed.identity);
        assert_eq!(parsed.child, ["claude"]);
        assert_eq!(confine_step("claude-code", NO_INSTANCE, false), None);
        assert_eq!(confine_step("aider", NO_INSTANCE, true), None);
        for reason in [
            "confined_by_namespace",
            "no_scope",
            "no_namespace_on_backend",
            NOT_CHECKED_YET,
            "made_up",
        ] {
            assert_eq!(confine_step("claude-code", reason, true), None, "{reason}");
        }
        assert_eq!(
            confine_step("claude-code", "namespace_mismatch", true).map(|s| s.label),
            Some("Start it in a jail")
        );
    }

    #[test]
    fn an_instance_view_carries_labels_never_paths_of_the_project() {
        let live = facts(
            ID,
            true,
            Some((Trust::Observed, Reason::ConfinedByNamespace)),
        );
        let view = instance_view(&live, Some(&label("confined", "confined_by_namespace")));
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["trust"], "observed");
        assert_eq!(json["trust_source"], "jail");
        assert_eq!(json["project"], "payments-api");
        assert_eq!(json["mode"], "enforce");
        assert_eq!(json["started_at"], "2026-10-16T09:12:03Z");
        assert_eq!(json["sessions"][0]["session"], "a1b2c3d4");
        assert_eq!(json["sessions"][0]["case_id"], "cmd:contain:3");
        assert_eq!(
            json["technical"]["scope_unit"],
            format!("innerwarden-contain-{ID}.scope")
        );
        let bare = instance_view(&facts(ID, false, None), None);
        let json = serde_json::to_value(&bare).unwrap();
        assert_eq!(json["trust_reason"], NOT_CHECKED_YET);
        assert!(json.get("last_activity_at").is_none());
        assert_eq!(json["sessions"], serde_json::json!([]));
    }

    #[test]
    fn an_unusable_profiles_file_is_said_with_its_reason_and_no_hidden_text() {
        let view = profiles_file_view("/etc/innerwarden/agent-profiles.toml: bad\u{202E}key\n x");
        assert_eq!(view.state, "invalid");
        assert!(
            view.sentence
                .contains("agent-profiles.toml: bad\\u{202E}key x"),
            "{}",
            view.sentence
        );
        assert!(!view.sentence.contains('\u{202E}'));
    }
}
