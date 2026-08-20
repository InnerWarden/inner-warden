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
//! So every line below is one of three states, and the third is never folded
//! into the second.

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
        }
    }
}

/// Observed facts. Every field is read live; `None` means "could not read",
/// which is deliberately different from `Some(false)`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    /// Guard mode as configured: "enforce", "dry-run", or None if unreadable.
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
    /// Number of guard decisions recorded. `None` = the record could not be read.
    pub decisions_recorded: Option<u64>,
    /// Whether the local dashboard answered.
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
        Some(other) => out.push(Finding::Unknown {
            what: format!("Guard mode reads as {other:?}, which I do not recognise."),
            why: "Expected enforce or dry-run. Treating this as unknown rather \
                  than assuming either."
                .into(),
        }),
        // Nothing was attempted, so nothing failed.
        //
        // This said "Guard mode could not be read. The config was unreadable."
        // and `main.rs` passes `mode: None` unconditionally, because the mode is
        // not persisted anywhere this command can see. So the sentence was not
        // occasionally wrong, it was wrong every single time, for every user,
        // on the first command a beginner runs after wiring an agent. It sent
        // them looking for a broken config file that does not exist and never
        // did.
        //
        // "Could not be read" and "there is nowhere to read it from" are
        // different claims, and only the second one is true here.
        None => out.push(Finding::Unknown {
            what: "Guard mode is not something this command can see yet.".into(),
            why: "It is not written anywhere `status` can read, so nothing was \
                  attempted and nothing failed. Screening still applies; this \
                  line is about what I can report, not about what is running."
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
        Some(false) => out.push(Finding::NotWorking {
            what: "Local dashboard is not answering.".into(),
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
    /// `main.rs` passes `mode: None` unconditionally, because the mode is not
    /// persisted anywhere this command can see. So that sentence was not
    /// occasionally wrong; it was wrong for every user, every run, and it named
    /// a broken config file that does not exist.
    ///
    /// Claiming a read failed when no read was attempted is the same defect as
    /// claiming something is off when it merely could not be established. This
    /// file exists to refuse the second one, so it must refuse the first.
    #[test]
    fn an_unavailable_mode_does_not_blame_a_config_file() {
        let mut f = healthy();
        f.mode = None;
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
            rendered.contains("not written anywhere"),
            "say the real reason, so nobody goes looking for the file:\n{rendered}"
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
