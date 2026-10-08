//! `innerwarden status` — one question, one honest answer: is this on, and is
//! it doing anything?
//!
//! ## Why this exists
//!
//! Every other command here answers part of the question. `agents` lists what
//! it recognised, `observe` shows recent records, `dashboard` opens a page. A
//! beginner who has just installed this wants to know one thing, and today has
//! to assemble it from three commands and know which three.
//!
//! Worse, the parts can each look fine while the whole is not. A guard in
//! dry-run reports a mode cheerfully; a guard wired to no agent screens nothing
//! and says nothing about it; an install with zero recorded decisions is
//! indistinguishable from one that is working on a quiet machine.
//!
//! ## The rule this file exists to enforce
//!
//! **Never report "off" when you mean "could not tell".** Six independent bugs
//! found on 2026-08-19 were the same mistake in different clothes: a firewall
//! that refused to answer reported as absent, an agent whose signature did not
//! match reported as no agent, a block that could not be lifted filed as lifted.
//! Each one sent someone to fix the wrong thing.
//!
//! So every line below is one of these states, and "could not tell" is never
//! folded into "off". Nor is "not set up yet", nor "an optional extra is not
//! running": each of those has its own state precisely so it cannot be reported
//! as a fault in the thing that protects the machine.

use innerwarden_agent_guard::agents::GuardMode;
use innerwarden_agent_guard::hook::HookProgram;
use std::fmt;

/// How old the newest recorded decision may be before it stops counting as
/// proof that commands are reaching the guard now.
///
/// The count alone was the proof, and a count never goes down: a hook that died
/// weeks ago left `[on] N screening decision(s) recorded` on screen for as long
/// as the record lasted. A week covers a quiet weekend and a short holiday
/// without calling a working install stale.
pub const EVIDENCE_STALE_AFTER_SECS: u64 = 7 * 24 * 60 * 60;

/// PURE: the evidence facts from the decision record, as `main.rs` hands them
/// over: `(decisions_recorded, newest_decision_age_secs, decisions_by_hand)`.
///
/// `None` for the record is a record that could not be read, which stays
/// unknown. Only decisions an agent's hook or the MCP proxy recorded count as
/// evidence; a check by hand was counted as well, so an install whose agent
/// hook had never fired said its commands "really are reaching the guard"
/// on the strength of the operator's own checks and drills (rc1-F20).
pub fn decision_evidence(
    record: Option<&innerwarden_graph::Graph>,
    now_ms: u64,
) -> (Option<u64>, Option<u64>, u64) {
    let Some(graph) = record else {
        return (None, None, 0);
    };
    let evidence = graph.screening_evidence();
    (
        Some(evidence.through_agents),
        evidence
            .newest_through_agents_ms
            .map(|ms| now_ms.saturating_sub(ms) / 1000),
        evidence.by_hand,
    )
}

/// A wired agent whose hook is not known to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookTrouble {
    pub agent: String,
    /// `Broken` or `Unknown`; an agent whose hook runs is never listed here.
    pub program: HookProgram,
    /// The command that rewrites the hook to a binary that is there.
    pub next: String,
    /// The wiring is an MCP proxy wrapper, not a hook: its servers cannot
    /// start rather than run unscreened, and the sentence says which.
    pub via_proxy: bool,
}

/// PURE: a duration a person reads at a glance, in its largest whole unit.
pub fn age_words(secs: u64) -> String {
    let (n, unit) = match secs {
        0..=59 => return "less than a minute".into(),
        60..=3_599 => (secs / 60, "minute"),
        3_600..=86_399 => (secs / 3_600, "hour"),
        _ => (secs / 86_400, "day"),
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

/// What we could establish about one aspect of the install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// Established working, with the evidence that established it.
    Working(String),
    /// Established NOT working, with what to do about it.
    NotWorking { what: String, next: String },
    /// Could not be established either way. Never rendered as "off".
    Unknown { what: String, why: String },
    /// Not set up yet. Distinct from Unknown: nothing is wrong, there is simply
    /// nothing here to read, and the reader needs a first step rather than a
    /// diagnosis.
    NotConfigured { what: String, next: String },
    /// Established not running, and that is fine: an optional extra nothing is
    /// protected any less without. Distinct from NotWorking, which is a fault,
    /// and from Unknown, which is an unanswered question.
    ///
    /// Without this variant the only way to say "the dashboard is not up" was
    /// `NotWorking`, which put a fully wired, enforcing machine under the
    /// headline "NOT fully protecting this machine" because an optional local
    /// UI was closed. That is this file's own mistake pointed at a new line.
    Optional { what: String, next: String },
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Finding::Working(what) => write!(f, "  [on]      {what}"),
            Finding::NotWorking { what, next } => {
                write!(f, "  [off]     {what}\n            try: {next}")
            }
            Finding::Unknown { what, why } => {
                write!(f, "  [unknown] {what}\n            {why}")
            }
            Finding::NotConfigured { what, next } => {
                write!(f, "  [not set] {what}\n            start with: {next}")
            }
            Finding::Optional { what, next } => {
                write!(f, "  [idle]    {what}\n            if you want it: {next}")
            }
        }
    }
}

/// PURE: collapse the per-agent wiring modes into the one line `status` prints.
///
/// The mode IS readable: `agents_ops::rows` reads each agent's wiring back and
/// reports what it actually DOES. `status` fetched those rows already and then
/// threw the modes away, so the first command a beginner runs after
/// `innerwarden enforce` told them the mode was not knowable.
///
/// Two rules, both in the same direction as the rest of this file:
///
/// * one unreadable wiring makes the whole answer `None`, because "enforce" as
///   a summary of wiring nobody could read back is a guess, and
/// * agents that disagree, or a single agent whose own wiring disagrees, are
///   reported as `mixed` rather than rounded to the reassuring half.
pub fn aggregate_mode(modes: &[Option<GuardMode>]) -> Option<String> {
    if modes.is_empty() || modes.iter().any(Option::is_none) {
        return None;
    }
    let mut records = false;
    let mut blocks = false;
    for mode in modes.iter().flatten() {
        match mode {
            GuardMode::Monitor => records = true,
            GuardMode::Enforce => blocks = true,
            GuardMode::Mixed => {
                records = true;
                blocks = true;
            }
        }
    }
    match (records, blocks) {
        (true, true) => Some("mixed".into()),
        (true, false) => Some("monitor".into()),
        (false, true) => Some("enforce".into()),
        (false, false) => None,
    }
}

/// PURE: is this HTTP body a local InnerWarden dashboard answering?
///
/// Something listening on the port is NOT the question. The check-command
/// contract shares that port, so a bare TCP connect would report "dashboard is
/// up" for an Active Defence agent, a stale `serve`, or anything else that
/// happens to be bound. Only the dashboard's own meta payload counts.
pub fn is_dashboard_answer(body: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .is_some_and(|payload| {
            payload.get("edition").is_some() && payload.get("guardrail").is_some()
        })
}

/// Observed facts. Every field is read live; `None` means "could not read",
/// which is deliberately different from `Some(false)`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    /// What the wiring of the connected agents actually DOES, summarised:
    /// "enforce", "monitor" (alias "dry-run"), or "mixed" when it disagrees with
    /// itself. `None` when nothing is wired to have a mode, or when a wiring
    /// exists and could not be read back. See [`aggregate_mode`].
    pub mode: Option<String>,
    /// True when this install has simply not been set up yet: no config, no
    /// records, nothing wired. A fresh box is not a broken one, and telling a
    /// beginner three things "could not be read" when the answer is "you have
    /// not run setup" sends them looking for a fault that does not exist.
    pub never_configured: bool,
    /// Agents this install is wired into whose hook can run. Empty means none
    /// wired, which is not the same as none present.
    pub wired_agents: Vec<String>,
    /// Agents that are wired, but whose hook runs a program that is not there
    /// (or could not be checked). Never also in `wired_agents`: a hook that
    /// cannot start screens nothing, whatever its text says.
    pub hook_trouble: Vec<HookTrouble>,
    /// Whether ANY agent process was visible, regardless of wiring.
    pub any_agent_seen: Option<bool>,
    /// Commands an agent's hook or the MCP proxy screened and recorded, allows
    /// included. Checks run by hand are NOT here (see `decisions_by_hand`).
    /// `Some(0)` is a record that exists with nothing an agent sent in it yet;
    /// `None` is a record that could not be read, which is a different sentence
    /// and must stay one.
    pub decisions_recorded: Option<u64>,
    /// How long ago the newest of those was recorded. `None` when none says
    /// when, which is "cannot tell", not "never".
    pub newest_decision_age_secs: Option<u64>,
    /// Checks run by hand (`innerwarden check`, and the drills and verify runs
    /// that screen through it). They prove the guard answers, not that an
    /// agent's commands reach it, so they only explain an empty count.
    pub decisions_by_hand: u64,
    /// Whether the local dashboard answered. `None` when it was not probed.
    pub dashboard_reachable: Option<bool>,
}

/// PURE: turn observed facts into findings a beginner can act on.
pub fn assess(facts: &Facts) -> Vec<Finding> {
    let mut out = Vec::new();

    // A fresh install answers in one line instead of three diagnoses.
    if facts.never_configured {
        out.push(Finding::NotConfigured {
            what: "This machine has InnerWarden installed but not set up: no \
                   config, no wired agent, and nothing screened yet."
                .into(),
            next: "innerwarden setup".into(),
        });
        return out;
    }

    // ── Mode ────────────────────────────────────────────────────────────────
    match facts.mode.as_deref() {
        Some("enforce") => out.push(Finding::Working(
            "Guard mode is enforce: a refused command is actually refused.".into(),
        )),
        Some("dry-run") | Some("monitor") => out.push(Finding::NotWorking {
            what: "Guard mode is dry-run: refusals are recorded, not applied.".into(),
            next: "innerwarden enforce".into(),
        }),
        // Some wiring records and some of it blocks. Rounding this to "enforce"
        // would tell someone they are covered while part of what they run is
        // not, so it is reported as the half that is not protecting.
        Some("mixed") => out.push(Finding::NotWorking {
            what: "Guard mode is mixed: some of the wiring records, some of it \
                   blocks, so part of what you run is not actually refused."
                .into(),
            next: "innerwarden enforce".into(),
        }),
        Some(other) => out.push(Finding::Unknown {
            what: format!("Guard mode reads as {other:?}, which I do not recognise."),
            why: "Expected enforce or dry-run. Treating this as unknown rather \
                  than assuming either."
                .into(),
        }),
        // Nothing is wired, so there is no mode to have. Nothing was attempted
        // here and nothing failed, and saying otherwise sends the reader to a
        // config file that does not exist. The wiring line below is the one
        // that carries the actual news.
        None if facts.wired_agents.is_empty() && !facts.hook_trouble.is_empty() => {
            out.push(Finding::Unknown {
                what: "No wired agent has a hook that runs, so no guard mode is in \
                       effect."
                    .into(),
                why: "The wiring lines below say what is wrong and how to fix it.".into(),
            })
        }
        None if facts.wired_agents.is_empty() => out.push(Finding::Unknown {
            what: "No agent is wired, so there is no guard mode to report yet.".into(),
            why: "A mode belongs to wiring: connect an agent and this line \
                  becomes enforce or dry-run."
                .into(),
        }),
        // Wiring exists and did not read back as either mode. THIS one is a
        // genuine failed read, and it names the wiring rather than inventing a
        // broken file elsewhere.
        None => out.push(Finding::Unknown {
            what: "An agent is wired, but what that wiring DOES did not read \
                   back as enforce or dry-run."
                .into(),
            why: "Screening still applies; I will not guess which of the two it \
                  is. `innerwarden agents` shows the wiring this was read from."
                .into(),
        }),
    }

    // ── Wiring ──────────────────────────────────────────────────────────────
    // A hook is only text. Claude Code runs it, the exec fails, it reports a
    // non-blocking hook error and the command goes ahead unscreened. This line
    // said `[on] Wired into 1: claude-code.` on a Mac whose hook pointed at a
    // cleaned build for weeks, so an agent is only "wired" here once the
    // program its hook runs is there.
    for trouble in &facts.hook_trouble {
        match &trouble.program {
            HookProgram::Broken { problem, .. } => out.push(Finding::NotWorking {
                what: format!(
                    "{} is wired, but {problem}, so {}.",
                    trouble.agent,
                    if trouble.via_proxy {
                        "its MCP servers cannot start"
                    } else {
                        "none of its commands are screened"
                    }
                ),
                next: trouble.next.clone(),
            }),
            HookProgram::Unknown { why, .. } => out.push(Finding::Unknown {
                what: format!(
                    "{} is wired, but I could not confirm its {} can run.",
                    trouble.agent,
                    if trouble.via_proxy {
                        "MCP proxy"
                    } else {
                        "hook"
                    }
                ),
                why: format!("{why}. If it does not, `{}` rewrites it.", trouble.next),
            }),
            HookProgram::Runs => {}
        }
    }
    if !facts.wired_agents.is_empty() {
        out.push(Finding::Working(format!(
            "Wired into {}: {}.",
            facts.wired_agents.len(),
            facts.wired_agents.join(", ")
        )));
    } else if facts.hook_trouble.is_empty() {
        match facts.any_agent_seen {
            Some(true) => out.push(Finding::NotWorking {
                what: "An agent is running but nothing is wired to the guard, so \
                       its commands are not screened."
                    .into(),
                next: "innerwarden agents connect --all --monitor".into(),
            }),
            Some(false) => out.push(Finding::NotWorking {
                what: "No agent is wired, and none of the agents I know by name \
                       are running."
                    .into(),
                next: "start your agent, then: innerwarden agents connect --all --monitor".into(),
            }),
            None => out.push(Finding::Unknown {
                what: "Could not tell whether any agent is running.".into(),
                why: "Process inspection failed. An agent may well be running; I \
                      simply could not look."
                    .into(),
            }),
        }
    }

    // ── Evidence ────────────────────────────────────────────────────────────
    match facts.decisions_recorded {
        Some(0) if facts.decisions_by_hand > 0 => out.push(Finding::Unknown {
            what: format!(
                "No screening decisions from an agent recorded yet, only {} check(s) run \
                 by hand.",
                facts.decisions_by_hand
            ),
            why: "A check by hand (a drill or a verify run is one too) shows the guard \
                  answers, not that your agent's commands reach it. Run a command \
                  through your agent and check again."
                .into(),
        }),
        Some(0) => out.push(Finding::Unknown {
            what: "No screening decisions recorded yet.".into(),
            why: "On a quiet machine that is normal; on a busy one it means \
                  nothing is reaching the guard. Run a command through your \
                  agent and check again."
                .into(),
        }),
        // The count only ever grows, so on its own it proves something reached
        // the guard ONCE. Whether commands are reaching it NOW is the time of
        // the newest one.
        Some(n) => match facts.newest_decision_age_secs {
            Some(age) if age <= EVIDENCE_STALE_AFTER_SECS => out.push(Finding::Working(format!(
                "{n} screening decision(s) recorded, the newest {} ago, so commands \
                 really are reaching the guard.",
                age_words(age)
            ))),
            Some(age) => out.push(Finding::Unknown {
                what: format!(
                    "{n} screening decision(s) recorded, but the newest is {} old.",
                    age_words(age)
                ),
                why: "That is too old to show commands are reaching the guard now. If \
                      your agent has run commands since, they were not screened: \
                      restart it so it reloads its hook, run one command through it, \
                      and check again. `innerwarden agents` shows how each agent is \
                      wired."
                    .into(),
            }),
            None => out.push(Finding::Unknown {
                what: format!(
                    "{n} screening decision(s) recorded, but none says when it was \
                     made."
                ),
                why: "So I cannot tell whether commands are reaching the guard now. \
                      Run a command through your agent and check again."
                    .into(),
            }),
        },
        None => out.push(Finding::Unknown {
            what: "The decision record could not be read.".into(),
            why: "Without it I cannot tell whether anything has been screened, \
                  and I will not guess."
                .into(),
        }),
    }

    // ── Dashboard ───────────────────────────────────────────────────────────
    match facts.dashboard_reachable {
        Some(true) => out.push(Finding::Working("Local dashboard is answering.".into())),
        // Not a fault. The dashboard is a window onto what was screened, and a
        // closed window screens nothing less. Reported as `off` it dragged an
        // otherwise perfect install under "NOT fully protecting this machine",
        // which is this file's own mistake wearing a different hat.
        Some(false) => out.push(Finding::Optional {
            what: "The local dashboard is not running. It is optional, and \
                   nothing is screened any less without it. If you started one \
                   on another address, this line cannot see it."
                .into(),
            next: "innerwarden dashboard".into(),
        }),
        None => out.push(Finding::Unknown {
            what: "Did not probe the dashboard.".into(),
            why: "Nothing was concluded about it either way.".into(),
        }),
    }

    out
}

/// Is this install doing its job? Only `Working` on the things that matter.
///
/// `Optional` findings never move the verdict. An extra that is not running is
/// not a hole in what protects the machine, and letting one set the headline is
/// how "everything here is fine" became a sentence this command could never
/// print for any install at all.
pub fn headline(findings: &[Finding]) -> &'static str {
    if findings
        .iter()
        .any(|f| matches!(f, Finding::NotConfigured { .. }))
    {
        return "InnerWarden is installed and waiting to be set up.";
    }
    let any_unknown = findings
        .iter()
        .any(|f| matches!(f, Finding::Unknown { .. }));
    let any_off = findings
        .iter()
        .any(|f| matches!(f, Finding::NotWorking { .. }));
    match (any_off, any_unknown) {
        (false, false) => "InnerWarden is on and screening.",
        (true, _) => "InnerWarden is installed but NOT fully protecting this machine.",
        (false, true) => "InnerWarden is on, but some things could not be verified.",
    }
}

/// The whole report.
pub fn render(facts: &Facts) -> String {
    let findings = assess(facts);
    let mut out = format!("\n  {}\n\n", headline(&findings));
    for f in &findings {
        out.push_str(&format!("{f}\n"));
    }
    out.push_str(
        "\n  [unknown] never means off. It means I could not establish it, and\n\
         \x20 saying otherwise would send you to fix the wrong thing.\n",
    );
    out
}

#[cfg(test)]
mod tests {
    /// A fresh box is not a broken one.
    ///
    /// Before this, a machine with InnerWarden installed but never set up
    /// answered with three separate "could not be read" diagnoses, which reads
    /// as three faults. Verified on three hosts (Ubuntu 26.04/k7.0, 24.04/k6.17
    /// x86_64, and 22.04/k6.8 aarch64) — identical wall of unknowns on each.
    ///
    /// The reader needs a first step, not a diagnosis.
    #[test]
    fn a_fresh_install_gets_one_instruction_not_three_diagnoses() {
        let facts = Facts {
            never_configured: true,
            ..Facts::default()
        };
        let findings = assess(&facts);
        assert_eq!(findings.len(), 1, "one line, not a wall: {findings:?}");
        match &findings[0] {
            Finding::NotConfigured { next, .. } => assert_eq!(next, "innerwarden setup"),
            other => panic!("a fresh install must be told what to run: {other:?}"),
        }
        assert_eq!(
            headline(&findings),
            "InnerWarden is installed and waiting to be set up."
        );
    }

    /// The short-circuit must not swallow a real problem: once anything IS
    /// configured, every check runs again.
    #[test]
    fn a_configured_install_is_still_assessed_in_full() {
        let mut f = healthy();
        f.never_configured = false;
        assert!(assess(&f).len() > 1);
    }

    use super::*;

    fn healthy() -> Facts {
        Facts {
            never_configured: false,
            mode: Some("enforce".into()),
            wired_agents: vec!["claude-code".into()],
            hook_trouble: vec![],
            any_agent_seen: Some(true),
            decisions_recorded: Some(42),
            newest_decision_age_secs: Some(90),
            decisions_by_hand: 0,
            dashboard_reachable: Some(true),
        }
    }

    /// Measured on a clean box: install, `agents connect --all`, then `status`.
    /// The very next line a beginner sees was
    ///
    ///   [unknown] Guard mode could not be read.
    ///             The config was unreadable.
    ///
    /// Claiming a read failed when no read was attempted is the same defect as
    /// claiming something is off when it merely could not be established. This
    /// file exists to refuse the second one, so it must refuse the first.
    ///
    /// With nothing wired there is no wiring to read a mode from, so this is
    /// still the case where no read happens and no read may be blamed.
    #[test]
    fn an_unavailable_mode_does_not_blame_a_config_file() {
        let mut f = healthy();
        f.mode = None;
        f.wired_agents.clear();
        let rendered = render(&f);
        assert!(
            !rendered.contains("config was unreadable"),
            "nothing was read, so nothing was unreadable:\n{rendered}"
        );
        assert!(
            !rendered.contains("could not be read"),
            "'could not be read' claims an attempt that never happened:\n{rendered}"
        );
        assert!(
            rendered.contains("no guard mode to report yet"),
            "say the real reason, so nobody goes looking for the file:\n{rendered}"
        );
    }

    /// The other half of the same rule. Once an agent IS wired, a mode that
    /// does not read back is a read that really was attempted and really did
    /// fail, and the line must say so against the wiring it came from rather
    /// than repeat "there is nowhere to read it from", which by then is false.
    #[test]
    fn a_wired_agent_with_an_unreadable_mode_says_which_read_failed() {
        let mut f = healthy();
        f.mode = None;
        let rendered = render(&f);
        assert!(
            rendered.contains("An agent is wired"),
            "name the wiring the failed read came from:\n{rendered}"
        );
        assert!(
            rendered.contains("innerwarden agents"),
            "point at the command that shows that wiring:\n{rendered}"
        );
        assert!(
            !rendered.contains("[off]"),
            "an unreadable mode is not an off mode:\n{rendered}"
        );
    }

    /// REGRESSION ANCHOR for the whole reason this fix exists.
    ///
    /// `main.rs` hard-coded `mode: None`, so the line a beginner reads
    /// IMMEDIATELY after `innerwarden enforce` succeeds said the mode was not
    /// knowable. The rows it needed were already in hand: `agents_ops::rows`
    /// reads each wiring back and reports monitor or enforce.
    ///
    /// FAILS ON REVERT: drop the modes on the floor again and `aggregate_mode`
    /// gets `[]`, which is `None`, which is the [unknown] line.
    #[test]
    fn a_readable_wiring_is_summarised_into_a_mode() {
        assert_eq!(
            aggregate_mode(&[Some(GuardMode::Enforce)]).as_deref(),
            Some("enforce")
        );
        assert_eq!(
            aggregate_mode(&[Some(GuardMode::Monitor), Some(GuardMode::Monitor)]).as_deref(),
            Some("monitor")
        );
        // The mode line for an enforcing install must read as protection.
        let mut f = healthy();
        f.mode = aggregate_mode(&[Some(GuardMode::Enforce)]);
        match &assess(&f)[0] {
            Finding::Working(what) => assert!(
                what.contains("enforce"),
                "an enforcing install must say enforce: {what}"
            ),
            other => panic!("enforce must read as protection: {other:?}"),
        }
    }

    /// One wiring nobody could read back poisons the summary: "enforce" would
    /// then be a claim about a config that was never understood.
    #[test]
    fn one_unreadable_wiring_makes_the_whole_mode_unknown() {
        assert_eq!(aggregate_mode(&[Some(GuardMode::Enforce), None]), None);
        assert_eq!(aggregate_mode(&[]), None, "nothing wired has no mode");
    }

    /// Disagreeing wiring is never rounded to the reassuring half: two agents
    /// where one records and one blocks is not an enforcing machine.
    #[test]
    fn disagreeing_wiring_is_reported_as_mixed_not_as_enforce() {
        assert_eq!(
            aggregate_mode(&[Some(GuardMode::Enforce), Some(GuardMode::Monitor)]).as_deref(),
            Some("mixed")
        );
        assert_eq!(
            aggregate_mode(&[Some(GuardMode::Mixed)]).as_deref(),
            Some("mixed")
        );
        let mut f = healthy();
        f.mode = Some("mixed".into());
        let findings = assess(&f);
        match &findings[0] {
            Finding::NotWorking { what, next } => {
                assert!(what.contains("mixed"), "{what}");
                assert_eq!(next, "innerwarden enforce");
            }
            other => panic!("mixed wiring must not read as protection: {other:?}"),
        }
        assert!(headline(&findings).contains("NOT fully protecting"));
    }

    /// The dashboard is an optional window, not a wall.
    ///
    /// Reported as `[off]`, a closed dashboard put a fully wired, enforcing,
    /// actively screening install under "NOT fully protecting this machine" and
    /// handed the reader a fault to chase that was never a fault.
    ///
    /// FAILS ON REVERT: make the not-running dashboard `NotWorking` again and
    /// the headline flips.
    #[test]
    fn a_closed_dashboard_is_not_a_hole_in_protection() {
        let mut f = healthy();
        f.dashboard_reachable = Some(false);
        let findings = assess(&f);
        assert!(
            findings.iter().any(
                |x| matches!(x, Finding::Optional { next, .. } if next == "innerwarden dashboard")
            ),
            "a dashboard that is not running is optional, not broken: {findings:?}"
        );
        assert_eq!(
            headline(&findings),
            "InnerWarden is on and screening.",
            "an optional extra must not set the verdict: {findings:?}"
        );
        let rendered = render(&f);
        assert!(
            !rendered.contains("[off]"),
            "nothing here is off:\n{rendered}"
        );
    }

    /// There must EXIST an install this command calls fine, or "fine" is not a
    /// verdict it can reach and every reader learns to ignore the headline.
    #[test]
    fn a_fully_working_install_has_a_verdict_it_can_reach() {
        let mut f = healthy();
        f.dashboard_reachable = Some(false);
        f.mode = Some("enforce".into());
        assert_eq!(headline(&assess(&f)), "InnerWarden is on and screening.");
    }

    /// Anything at all listening on the port is not a dashboard: the
    /// check-command contract shares it, and so can an Active Defence agent.
    #[test]
    fn only_the_dashboards_own_payload_counts_as_an_answer() {
        assert!(is_dashboard_answer(
            r#"{"version":"1.3.2","edition":"community","guardrail":{"mode":"enforce","guarded_agents":1}}"#
        ));
        assert!(!is_dashboard_answer("not json at all"));
        assert!(!is_dashboard_answer(r#"{"error":"unauthorized"}"#));
        assert!(
            !is_dashboard_answer(r#"{"edition":"community"}"#),
            "half a payload is not the dashboard answering"
        );
    }

    #[test]
    fn a_healthy_install_says_so_plainly() {
        let findings = assess(&healthy());
        assert!(findings.iter().all(|f| matches!(f, Finding::Working(_))));
        assert_eq!(headline(&findings), "InnerWarden is on and screening.");
    }

    /// The rule this file exists for: unreadable is never rendered as off.
    ///
    /// Six independent bugs found on 2026-08-19 were this same mistake — a
    /// firewall that refused to answer reported as absent, an agent whose
    /// signature did not match reported as no agent. Each sent someone to fix
    /// the wrong thing.
    #[test]
    fn unreadable_is_never_reported_as_off() {
        let facts = Facts {
            never_configured: false,
            mode: None,
            wired_agents: vec![],
            hook_trouble: vec![],
            any_agent_seen: None,
            decisions_recorded: None,
            newest_decision_age_secs: None,
            decisions_by_hand: 0,
            dashboard_reachable: None,
        };
        for finding in assess(&facts) {
            assert!(
                !matches!(finding, Finding::NotWorking { .. }),
                "nothing was established, so nothing may be reported as off: {finding:?}"
            );
        }
    }

    /// Dry-run is a real "off" for the thing a user cares about: it records
    /// refusals instead of applying them, and must not read as protection.
    #[test]
    fn dry_run_is_reported_as_not_protecting() {
        let mut f = healthy();
        f.mode = Some("dry-run".into());
        let findings = assess(&f);
        let mode = &findings[0];
        match mode {
            Finding::NotWorking { what, next } => {
                assert!(what.contains("not applied") || what.contains("recorded"));
                assert_eq!(next, "innerwarden enforce");
            }
            other => panic!("dry-run must not read as protection: {other:?}"),
        }
        assert!(headline(&findings).contains("NOT fully protecting"));
    }

    /// An agent running but unwired is the most dangerous quiet state: the user
    /// believes they are covered and no command is screened.
    #[test]
    fn a_running_but_unwired_agent_is_called_out() {
        let mut f = healthy();
        f.wired_agents.clear();
        f.any_agent_seen = Some(true);
        let findings = assess(&f);
        let next = findings
            .iter()
            .find_map(|x| match x {
                Finding::NotWorking { what, next } if what.contains("not screened") => Some(next),
                _ => None,
            })
            .expect("an unwired running agent must be called out");

        // The remedy must be a command that WORKS, not merely a plausible one.
        //
        // It used to be `innerwarden hook <your-agent>`, and this assertion
        // pinned the substring "hook", so the string could rot without the test
        // noticing. It had: run with stdin closed, `innerwarden hook claude-code`
        // prints nothing, wires nothing and exits 0. A beginner following the
        // one line status gives them ends up exactly as unprotected as before,
        // with no error to tell them so.
        //
        // `agents connect --all --monitor` is what setup.rs names as the
        // non-interactive user's primary action, and it reports what it did per
        // integration.
        assert_eq!(next, "innerwarden agents connect --all --monitor");
        assert!(
            !next.contains("hook <"),
            "a placeholder the user has to fill in is not a command they can run"
        );
    }

    /// Zero decisions is genuinely ambiguous and must be said so, not dressed
    /// up as either working or broken.
    #[test]
    fn zero_decisions_is_unknown_not_a_verdict() {
        let mut f = healthy();
        f.decisions_recorded = Some(0);
        let findings = assess(&f);
        assert!(findings.iter().any(|x| matches!(
            x,
            Finding::Unknown { what, why }
                if what.contains("No screening decisions") && why.contains("quiet machine")
        )));
    }

    /// rc1-F20: an install whose agent hook never fired, where the operator ran
    /// checks (or a drill, or a verify) by hand, said "N screening decision(s)
    /// recorded ... so commands really are reaching the guard".
    ///
    /// FAILS ON REVERT: count every decision in the record again and the checks
    /// become a recent count that reads as `[on]`.
    #[test]
    fn checks_by_hand_never_say_an_agent_reaches_the_guard() {
        let mut graph = innerwarden_graph::Graph::new();
        for seq in 0..5 {
            graph.ingest_verdict_with_origin(
                "local",
                seq,
                "curl http://203.0.113.9/x",
                &serde_json::json!({"recommendation": "deny", "explanation": "x"}),
                innerwarden_graph::DecisionContext {
                    mode: innerwarden_graph::DecisionMode::Check,
                    outcome: innerwarden_graph::DecisionOutcome::Screened,
                    recorded_at_ms: Some(1_000_000),
                },
                &innerwarden_graph::DecisionOrigin {
                    channel: Some(innerwarden_graph::DecisionChannel::Check),
                    ..Default::default()
                },
            );
        }
        let (recorded, age, by_hand) = decision_evidence(Some(&graph), 1_030_000);
        assert_eq!((recorded, age, by_hand), (Some(0), None, 5));

        let mut f = healthy();
        f.decisions_recorded = recorded;
        f.newest_decision_age_secs = age;
        f.decisions_by_hand = by_hand;
        let findings = assess(&f);
        assert!(
            !findings
                .iter()
                .any(|x| matches!(x, Finding::Working(what) if what.contains("reaching"))),
            "{findings:?}"
        );
        assert!(
            findings.iter().any(|x| matches!(
                x,
                Finding::Unknown { what, why }
                    if what.contains("only 5 check(s) run by hand")
                        && why.contains("not that your agent's commands reach it")
            )),
            "{findings:?}"
        );
        assert_ne!(headline(&findings), "InnerWarden is on and screening.");
        // An unreadable record stays unknown, never zero.
        assert_eq!(decision_evidence(None, 0), (None, None, 0));
    }

    /// Facts for an install whose only agent is wired to a hook whose program
    /// the caller found in `fact`, as `main.rs` hands them over: an agent whose
    /// hook does not run is in `hook_trouble` and NOT in `wired_agents`, and
    /// with no readable wiring left there is no mode.
    fn wired_to(program: &str, fact: ProgramFact, next: &str) -> Facts {
        let mut f = healthy();
        match judge_hook_program(program, fact) {
            HookProgram::Runs => {}
            verdict => {
                f.wired_agents.clear();
                f.mode = None;
                f.hook_trouble = vec![HookTrouble {
                    agent: "claude-code".into(),
                    program: verdict,
                    next: next.into(),
                    via_proxy: false,
                }];
            }
        }
        f
    }

    use innerwarden_agent_guard::hook::{judge_hook_program, ProgramFact};

    /// An absolute program path on this platform. `/x` is not absolute on
    /// Windows, where this suite also runs.
    fn abs(dir: &str) -> String {
        if cfg!(windows) {
            format!(r"C:\{dir}\innerwarden.exe")
        } else {
            format!("/{dir}/innerwarden")
        }
    }

    /// REGRESSION ANCHOR, measured on a real Mac on 2026-09-30.
    ///
    /// The Claude Code hook pointed at a `target/release` build that had been
    /// cleaned. Claude Code ran the hook, the exec failed as a non-blocking
    /// error, and nothing was screened for weeks, while this command said
    /// `[on] Wired into 1: claude-code.` under "on and screening".
    ///
    /// FAILS ON REVERT: drop the `hook_trouble` findings and nothing names the
    /// path, the remedy is gone, and the headline claims protection.
    #[test]
    fn a_wired_hook_whose_program_is_gone_is_not_on() {
        let program = abs("nonexistent/target/release");
        let f = wired_to(
            &program,
            ProgramFact::Missing,
            "innerwarden install claude-code --monitor",
        );
        let findings = assess(&f);
        let (what, next) = findings
            .iter()
            .find_map(|x| match x {
                Finding::NotWorking { what, next } if what.contains("claude-code") => {
                    Some((what, next))
                }
                _ => None,
            })
            .expect("a dead hook must be reported as not working");
        assert_eq!(
            *what,
            format!(
                "claude-code is wired, but its hook runs {program}, which does not \
                 exist, so none of its commands are screened."
            )
        );
        assert_eq!(next, "innerwarden install claude-code --monitor");
        assert_eq!(
            headline(&findings),
            "InnerWarden is installed but NOT fully protecting this machine."
        );
        let rendered = render(&f);
        assert!(!rendered.contains("Wired into"), "{rendered}");
        assert!(
            !rendered.contains("No agent is wired"),
            "an agent IS wired; its hook is what is broken:\n{rendered}"
        );
        assert!(
            rendered.contains("try: innerwarden install claude-code --monitor"),
            "{rendered}"
        );
    }

    /// The other side of the same line: a hook whose program is there stays on.
    #[test]
    fn a_wired_hook_whose_program_runs_stays_on() {
        let f = wired_to(&abs("usr/local/bin"), ProgramFact::Executable, "unused");
        let findings = assess(&f);
        assert!(findings
            .iter()
            .any(|x| matches!(x, Finding::Working(what) if what == "Wired into 1: claude-code.")));
        assert_eq!(headline(&findings), "InnerWarden is on and screening.");
    }

    #[test]
    fn a_wired_hook_whose_program_is_not_executable_is_not_on() {
        let program = abs("opt/iw");
        let f = wired_to(
            &program,
            ProgramFact::NotExecutable,
            "innerwarden install claude-code",
        );
        let findings = assess(&f);
        let expected = format!("{program}, which is not an executable file");
        assert!(
            findings.iter().any(|x| matches!(
                x,
                Finding::NotWorking { what, next }
                    if what.contains(&expected)
                        && next == "innerwarden install claude-code"
            )),
            "{findings:?}"
        );
        assert!(headline(&findings).contains("NOT fully protecting"));
    }

    #[test]
    fn a_wired_hook_whose_bare_program_is_not_on_path_is_not_on() {
        let f = wired_to(
            "innerwarden",
            ProgramFact::Missing,
            "innerwarden install claude-code",
        );
        let findings = assess(&f);
        assert!(
            findings.iter().any(|x| matches!(
                x,
                Finding::NotWorking { what, .. }
                    if what.contains("its hook runs `innerwarden`, which is not on PATH")
            )),
            "{findings:?}"
        );
        assert!(headline(&findings).contains("NOT fully protecting"));
    }

    /// A hook that could not be checked is unknown, never off, and never on.
    #[test]
    fn a_hook_that_could_not_be_checked_is_unknown_not_off() {
        let f = wired_to(
            &abs("opt/iw"),
            ProgramFact::Unreadable,
            "innerwarden install claude-code",
        );
        let findings = assess(&f);
        assert!(
            findings.iter().any(|x| matches!(
                x,
                Finding::Unknown { what, why }
                    if what == "claude-code is wired, but I could not confirm its hook can run."
                        && why.contains("`innerwarden install claude-code` rewrites it")
            )),
            "{findings:?}"
        );
        assert!(
            !findings.iter().any(
                |x| matches!(x, Finding::NotWorking { what, .. } if what.contains("claude-code"))
            ),
            "could not tell is not off: {findings:?}"
        );
        assert!(!render(&f).contains("Wired into"));
    }

    /// REGRESSION ANCHOR for the second line on the same screen.
    ///
    /// `[on] N screening decision(s) recorded, so commands really are reaching
    /// the guard` was decided by the all-time count, which never goes down. With
    /// a dead hook it stayed on forever. It is now the time of the newest
    /// decision that decides.
    ///
    /// FAILS ON REVERT: decide on the count alone and a month-old record reads
    /// as `[on] ... really are reaching the guard`.
    #[test]
    fn old_decisions_do_not_claim_commands_are_reaching_the_guard() {
        let mut f = healthy();
        f.newest_decision_age_secs = Some(30 * 24 * 60 * 60);
        let findings = assess(&f);
        assert!(
            !findings
                .iter()
                .any(|x| matches!(x, Finding::Working(what) if what.contains("reaching"))),
            "a month-old decision is not commands reaching the guard: {findings:?}"
        );
        let (what, why) = findings
            .iter()
            .find_map(|x| match x {
                Finding::Unknown { what, why } if what.contains("screening decision") => {
                    Some((what, why))
                }
                _ => None,
            })
            .expect("stale evidence must be reported, not dropped");
        assert_eq!(
            what,
            "42 screening decision(s) recorded, but the newest is 30 days old."
        );
        assert!(why.contains("restart it so it reloads its hook"), "{why}");
        assert!(why.contains("`innerwarden agents`"), "{why}");
        assert_eq!(
            headline(&findings),
            "InnerWarden is on, but some things could not be verified."
        );
    }

    #[test]
    fn recent_decisions_still_prove_commands_are_reaching_the_guard() {
        let f = healthy();
        let findings = assess(&f);
        assert!(
            findings.iter().any(|x| matches!(
                x,
                Finding::Working(what) if what == "42 screening decision(s) recorded, the \
                    newest 1 minute ago, so commands really are reaching the guard."
            )),
            "{findings:?}"
        );
    }

    /// The threshold is inclusive: a week old still counts, a second more does not.
    #[test]
    fn the_staleness_line_is_a_week() {
        let mut f = healthy();
        f.newest_decision_age_secs = Some(EVIDENCE_STALE_AFTER_SECS);
        assert_eq!(headline(&assess(&f)), "InnerWarden is on and screening.");
        f.newest_decision_age_secs = Some(EVIDENCE_STALE_AFTER_SECS + 1);
        assert_ne!(headline(&assess(&f)), "InnerWarden is on and screening.");
    }

    /// A record whose decisions say nothing about when cannot prove "now".
    #[test]
    fn decisions_without_a_time_do_not_claim_commands_are_reaching_the_guard() {
        let mut f = healthy();
        f.newest_decision_age_secs = None;
        let findings = assess(&f);
        assert!(
            findings.iter().any(|x| matches!(
                x,
                Finding::Unknown { what, .. } if what.contains("none says when it was made")
            )),
            "{findings:?}"
        );
        assert!(!findings
            .iter()
            .any(|x| matches!(x, Finding::Working(what) if what.contains("reaching"))));
    }

    #[test]
    fn ages_read_in_their_largest_whole_unit() {
        assert_eq!(age_words(5), "less than a minute");
        assert_eq!(age_words(60), "1 minute");
        assert_eq!(age_words(150), "2 minutes");
        assert_eq!(age_words(3_600), "1 hour");
        assert_eq!(age_words(86_400 * 3 + 5), "3 days");
    }

    /// A mode string nobody recognises is unknown, never silently treated as
    /// one of the two we do know.
    #[test]
    fn an_unrecognised_mode_is_not_guessed_at() {
        let mut f = healthy();
        f.mode = Some("paranoid".into());
        match &assess(&f)[0] {
            Finding::Unknown { what, .. } => assert!(what.contains("paranoid")),
            other => panic!("an unknown mode must not be assumed: {other:?}"),
        }
    }

    /// The report must state the rule, because a reader who does not know it
    /// will read [unknown] as [off] anyway.
    #[test]
    fn the_report_explains_what_unknown_means() {
        let text = render(&Facts::default());
        assert!(text.contains("never means off"));
        assert!(text.contains("fix the wrong thing"));
    }
}
