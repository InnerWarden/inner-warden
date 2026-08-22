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
use std::fmt;

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
    /// Agents this install is wired into. Empty means none wired, which is not
    /// the same as none present.
    pub wired_agents: Vec<String>,
    /// Whether ANY agent process was visible, regardless of wiring.
    pub any_agent_seen: Option<bool>,
    /// Commands screened and recorded, allows included. `Some(0)` is a record
    /// that exists with nothing in it yet; `None` is a record that could not be
    /// read, which is a different sentence and must stay one.
    pub decisions_recorded: Option<u64>,
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
    if !facts.wired_agents.is_empty() {
        out.push(Finding::Working(format!(
            "Wired into {}: {}.",
            facts.wired_agents.len(),
            facts.wired_agents.join(", ")
        )));
    } else {
        match facts.any_agent_seen {
            Some(true) => out.push(Finding::NotWorking {
                what: "An agent is running but nothing is wired to the guard, so \
                       its commands are not screened."
                    .into(),
                next: "innerwarden hook <your-agent>".into(),
            }),
            Some(false) => out.push(Finding::NotWorking {
                what: "No agent is wired, and none of the agents I know by name \
                       are running."
                    .into(),
                next: "start your agent, then: innerwarden hook <your-agent>".into(),
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
        Some(0) => out.push(Finding::Unknown {
            what: "No screening decisions recorded yet.".into(),
            why: "On a quiet machine that is normal; on a busy one it means \
                  nothing is reaching the guard. Run a command through your \
                  agent and check again."
                .into(),
        }),
        Some(n) => out.push(Finding::Working(format!(
            "{n} screening decision(s) recorded, so commands really are reaching \
             the guard."
        ))),
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
            any_agent_seen: Some(true),
            decisions_recorded: Some(42),
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
            any_agent_seen: None,
            decisions_recorded: None,
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
        assert!(findings.iter().any(|x| matches!(
            x,
            Finding::NotWorking { what, next }
                if what.contains("not screened") && next.contains("hook")
        )));
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
