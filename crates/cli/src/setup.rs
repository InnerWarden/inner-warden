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
    SetupOption {
        label: "Start Claude Code in the AI Jail every time",
        blurb: "adds one alias line to your shell, so `claude` starts inside the jail with the guard in it. Without it, `claude` starts as it always did, and `innerwarden contain -- claude` starts a jailed one. (optional)",
    },
];

/// The line the AI Jail extra adds to the shell: `claude` then starts
/// inside the jail, identified, with the guard in it.
pub const JAIL_ALIAS_LINE: &str = "alias claude='innerwarden contain --identity -- claude'";

/// The comment written above [`JAIL_ALIAS_LINE`], so the person can find
/// and remove it.
pub const JAIL_ALIAS_COMMENT: &str =
    "# InnerWarden: start Claude Code in the AI Jail (remove this and the next line to stop)";

/// PURE. The startup file of `shell` (`$SHELL`) under `home` where the AI
/// Jail extra adds its line: `~/.zshrc` for zsh, `~/.bashrc` for bash (on
/// macOS `~/.bash_profile`, which a login shell reads). `None` for any other
/// shell: the line is shown to be added by hand.
pub fn jail_alias_file(
    shell: Option<&str>,
    home: &std::path::Path,
    macos: bool,
) -> Option<std::path::PathBuf> {
    let name = std::path::Path::new(shell?).file_name()?.to_str()?;
    match name {
        "zsh" => Some(home.join(".zshrc")),
        "bash" if macos => Some(home.join(".bash_profile")),
        "bash" => Some(home.join(".bashrc")),
        _ => None,
    }
}

/// PURE. A startup file with the AI Jail line added at its end, or `None`
/// when it already defines `claude` as an alias (that one is left alone).
pub fn with_jail_alias(existing: &str) -> Option<String> {
    let defines_claude = existing.lines().any(|line| {
        let line = line.trim_start();
        line.strip_prefix("alias")
            .is_some_and(|rest| rest.trim_start().starts_with("claude="))
    });
    if defines_claude {
        return None;
    }
    let mut out = existing.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(JAIL_ALIAS_COMMENT);
    out.push('\n');
    out.push_str(JAIL_ALIAS_LINE);
    out.push('\n');
    Some(out)
}

/// What setup does about the AI Jail extra.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JailAliasOffer {
    /// Ask the person (default No).
    Ask,
    /// A jail does not start on this machine yet: say why, what to do, and
    /// the line to add once it does. Nothing is asked and nothing written.
    NotYet(Vec<String>),
    /// Say nothing: Claude Code is not here, or no jail backend is.
    Nothing,
}

/// PURE. What setup does about the AI Jail extra, from whether Claude Code
/// is here and what `contain` would do on this machine before it builds a
/// jail (`jail_here`: `None` without a backend it trusts; otherwise
/// whether a jail starts, or the lines `contain` says when it does not, the
/// last of which tells the person to run `contain` again).
pub fn jail_alias_offer(
    claude_here: bool,
    jail_here: Option<Result<(), Vec<String>>>,
) -> JailAliasOffer {
    match (claude_here, jail_here) {
        (true, Some(Ok(()))) => JailAliasOffer::Ask,
        (true, Some(Err(why))) => {
            let mut lines =
                vec!["The AI Jail does not start on this machine yet, so Claude Code is not set to start in it:".to_string()];
            lines.extend(
                why.into_iter()
                    .filter(|line| line.as_str() != crate::contain::RESTRICTION_ADVICE_END),
            );
            lines.push(
                "  Then, to start Claude Code in the AI Jail every time, add this line to your shell's startup file:"
                    .to_string(),
            );
            lines.push(format!("    {JAIL_ALIAS_LINE}"));
            JailAliasOffer::NotYet(lines)
        }
        _ => JailAliasOffer::Nothing,
    }
}

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
        "\nOptional extras can be enabled later (the command above starts in DRY RUN - observes, never blocks):\n  {prog} notify --telegram-token <T> --telegram-chat <C>   (or --slack-webhook / --discord-webhook <URL>)\n  {prog} llm set --url <URL> --model <M>  &&  {prog} llm set-key\n  {JAIL_ALIAS_LINE}   (add to your shell's startup file)\n  {prog} enforce                                          (leave dry run - start blocking)\n"
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

    /// The AI Jail extra adds one line, once, to the shell's own startup
    /// file, and never touches an alias for `claude` that is already there.
    /// It is off unless asked for: nothing here runs without the person's
    /// yes in the wizard.
    ///
    /// FAILS ON REVERT: add the line whatever the file holds in
    /// `with_jail_alias` and the second run adds it twice.
    #[test]
    fn the_jail_alias_is_added_once_and_never_over_one_of_the_persons() {
        let added = with_jail_alias("export PATH=$HOME/bin:$PATH").unwrap();
        assert_eq!(
            added,
            format!("export PATH=$HOME/bin:$PATH\n{JAIL_ALIAS_COMMENT}\n{JAIL_ALIAS_LINE}\n")
        );
        assert_eq!(with_jail_alias(&added), None, "added once");
        assert_eq!(with_jail_alias("alias claude='claude --verbose'\n"), None);
        assert_eq!(with_jail_alias("  alias  claude='x'\n"), None);
        assert!(with_jail_alias("alias claudex='x'\n").is_some());
        assert_eq!(
            with_jail_alias("").unwrap(),
            format!("{JAIL_ALIAS_COMMENT}\n{JAIL_ALIAS_LINE}\n")
        );
        let home = std::path::Path::new("/home/dev");
        assert_eq!(
            jail_alias_file(Some("/bin/zsh"), home, false),
            Some(home.join(".zshrc"))
        );
        assert_eq!(
            jail_alias_file(Some("/usr/bin/bash"), home, false),
            Some(home.join(".bashrc"))
        );
        assert_eq!(
            jail_alias_file(Some("/bin/bash"), home, true),
            Some(home.join(".bash_profile"))
        );
        assert_eq!(jail_alias_file(Some("/usr/bin/fish"), home, false), None);
        assert_eq!(jail_alias_file(None, home, false), None);
        assert_eq!(
            JAIL_ALIAS_LINE,
            "alias claude='innerwarden contain --identity -- claude'"
        );
    }

    /// The AI Jail extra is asked about only where a jail starts: on a host
    /// whose kernel restricts user namespaces and whose bwrap has no
    /// profile (stock Ubuntu 24.04), every `claude` after a yes would stop
    /// with the advice. There setup says why, what to do, and the line to
    /// add once it is done, and asks nothing.
    ///
    /// FAILS ON REVERT: ask wherever a backend is (`jail_backend().is_some()`,
    /// the check before this one) and the restricted host is asked.
    #[test]
    fn the_jail_alias_is_offered_only_where_a_jail_starts() {
        assert_eq!(jail_alias_offer(true, Some(Ok(()))), JailAliasOffer::Ask);
        assert_eq!(jail_alias_offer(true, None), JailAliasOffer::Nothing);
        assert_eq!(
            jail_alias_offer(false, Some(Ok(()))),
            JailAliasOffer::Nothing
        );
        let advice = crate::contain::userns_restriction_advice(
            Some("1\n"),
            false,
            std::path::Path::new("/usr/bin/bwrap"),
        )
        .expect("a restricted host");
        assert_eq!(
            jail_alias_offer(false, Some(Err(advice.clone()))),
            JailAliasOffer::Nothing
        );
        let JailAliasOffer::NotYet(lines) = jail_alias_offer(true, Some(Err(advice))) else {
            panic!("a restricted host is not asked");
        };
        let said = lines.join("\n");
        assert!(lines[0].starts_with("The AI Jail does not start on this machine yet"));
        assert!(said.contains("kernel.apparmor_restrict_unprivileged_userns = 1"));
        assert!(said.contains("sudo apparmor_parser -r /etc/apparmor.d/bwrap"));
        assert!(!said.contains("Then run this command again"), "{said}");
        assert_eq!(lines.last().unwrap().trim(), JAIL_ALIAS_LINE);
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
        assert!(s.contains(JAIL_ALIAS_LINE));
        // reflects the dry-run-first model + how to leave it
        assert!(s.contains("DRY RUN") && s.contains("innerwarden enforce"));
    }
}
