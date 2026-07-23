//! The first-run onboarding wizard's PURE half: the wording for the optional
//! extras and the non-interactive listing. The arrow-key prompts, the live agent
//! detection, and the wiring live in `setup_io.rs`.
//!
//! Onboarding has two parts:
//!   1. AGENTS - detected live (any of Claude Code, Cursor, Codex, Gemini, Goose,
//!      Aider, OpenClaw, Hermes Agent, ...), so the wizard is never
//!      Claude-Code-only. That list is dynamic, so it is built in the I/O layer
//!      from the detector. Agents without a reviewed adapter remain visibility
//!      only and require manual integration.
//!   2. EXTRAS - a fixed set of optional add-ons, each explained in a human line
//!      that says what it does, that it is OPTIONAL, and the cost of skipping.

/// One optional extra, listed in the non-interactive summary.
pub struct SetupOption {
    pub label: &'static str,
    /// One human line: what it does + that it is optional + the cost of skipping.
    pub blurb: &'static str,
}

/// The optional extras, described in the non-interactive summary. The interactive
/// wizard asks about each in its own guided step (see `setup_io`); none default on.
pub const EXTRAS: &[SetupOption] = &[
    SetupOption {
        label: "Alerts when a command is flagged",
        blurb: "ping Telegram / Slack / Discord (any mix) when a supported command hook is flagged, so you know without watching the terminal. Without it, no notification is sent. (optional)",
    },
    SetupOption {
        label: "Second opinion from my own AI model",
        blurb: "for the few AMBIGUOUS commands, let your own model auto-decide instead of alerting you. Needs your API endpoint + key, and costs one API call per ambiguous command. Fewer alerts reach you. (optional)",
    },
];

/// The listing printed when there is no terminal to prompt on (a piped
/// `curl | sh`, CI): how to inspect all detected agents and guard integrations
/// with reviewed configuration support. `prog` is the invoked name so examples match.
pub fn noninteractive_summary(prog: &str) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "{prog} - no terminal to prompt on; run `{prog} setup` in a terminal to choose interactively.\n\n\
         See your AI agents (including Claude Code, Cursor, Codex, Gemini, Goose, Aider, OpenClaw and Hermes Agent):\n  \
           {prog} agents                 see what's detected on this machine\n  \
           {prog} agents connect --all --monitor   guard every eligible integration in dry run\n  \
           {prog} agents auto-connect --monitor   opt in to new-agent discovery while the dashboard runs\n\n\
         Agents without a reviewed adapter are detection-only here; connect them manually and InnerWarden will not rewrite an unsupported format.\n\n\
         Optional extras (all off by default):\n"
    ));
    for o in EXTRAS {
        s.push_str(&format!("  • {}\n      {}\n", o.label, o.blurb));
    }
    s.push_str(&format!(
        "\nOptional extras can be enabled later (the command above starts in DRY RUN - observes, never blocks):\n  {prog} notify --telegram-token <T> --telegram-chat <C>   (or --slack-webhook / --discord-webhook <URL>)\n  {prog} llm set --url <URL> --model <M>  &&  {prog} llm set-key\n  {prog} enforce                                          (leave dry run - start blocking)\n"
    ));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_extra_explains_that_it_is_optional() {
        for o in EXTRAS {
            assert!(!o.blurb.trim().is_empty(), "{} has no blurb", o.label);
            assert!(
                o.blurb.to_lowercase().contains("optional"),
                "{} blurb must say optional: {}",
                o.label,
                o.blurb
            );
        }
    }

    #[test]
    fn noninteractive_summary_covers_agents_and_extras_and_is_not_claude_only() {
        let s = noninteractive_summary("innerwarden");
        // multi-agent, not Claude-Code-only
        assert!(
            s.contains("Cursor")
                && s.contains("Codex")
                && s.contains("OpenClaw")
                && s.contains("Hermes Agent")
        );
        assert!(s.contains("detection-only") && s.contains("manually"));
        assert!(s.contains("innerwarden agents connect --all"));
        assert!(s.contains("innerwarden agents auto-connect --monitor"));
        for o in EXTRAS {
            assert!(s.contains(o.label), "summary missing {}", o.label);
        }
        assert!(s.contains("innerwarden notify --telegram-token"));
        assert!(s.contains("innerwarden llm set"));
        // reflects the dry-run-first model + how to leave it
        assert!(s.contains("DRY RUN") && s.contains("innerwarden enforce"));
    }
}
