//! Thin I/O for the Active Defence gate: find + delegate to the licensed host CLI when
//! it is installed, otherwise print the (overridable) upsell. All wording + the
//! host-command set live in the pure `upsell` module. Excluded from the coverage
//! floor like the other `_io` adapters.

use std::process::ExitCode;

/// Locate the Active Defence host CLI (`innerwarden-ctl`) if it is installed: on
/// PATH, or in a standard install dir. Its presence is how the Community binary knows
/// Active Defence is on this machine.
fn find_ad_cli() -> Option<std::path::PathBuf> {
    const NAME: &str = "innerwarden-ctl";
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let p = dir.join(NAME);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    for base in ["/usr/local/bin", "/usr/bin", "/opt/innerwarden/bin"] {
        let p = std::path::Path::new(base).join(NAME);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// If Active Defence is installed, DELEGATE this command to it transparently
/// (`innerwarden <cmd> <args>` -> `innerwarden-ctl <cmd> <args>`) and return its
/// exit code. `None` when AD is not installed (the caller then upsells or errors).
/// This is a CATCH-ALL: any command the Community binary does not handle natively is
/// forwarded, so the single `innerwarden` CLI runs EVERY Active Defence host command on a
/// licensed box - not just a hard-coded list. (`innerwarden-ctl` enforces the
/// licence, so no host command runs without a valid one.)
/// Verbs this binary handles natively that ALSO exist in Active Defence.
///
/// The catch-all delegation only fires for a verb this binary does not know, so
/// these were unreachable on a licensed host: `innerwarden setup` always ran
/// the Community wizard and the host one could not be reached at all. Naming
/// them makes the overlap explicit instead of an accident of match order.
pub const SHARED_VERBS: &[&str] = &["setup", "dashboard", "upgrade", "uninstall"];

/// Is `verb` handled here AND by Active Defence?
pub fn is_shared_verb(verb: &str) -> bool {
    SHARED_VERBS.contains(&verb)
}

/// One line pointing at the host counterpart of a shared verb, when Active
/// Defence is installed. `None` when it is not, so a free-only machine is never
/// told about a command it does not have.
pub fn shared_verb_hint(verb: &str) -> Option<String> {
    if !is_shared_verb(verb) || find_ad_cli().is_none() {
        return None;
    }
    Some(format!(
        "  Active Defence has its own `{verb}` for the host layer:  innerwarden host {verb}"
    ))
}

pub fn try_delegate(command: &str, args: &[String]) -> Option<ExitCode> {
    let cli = find_ad_cli()?;
    let status = std::process::Command::new(cli)
        .arg(command)
        .args(args)
        .status();
    Some(match status {
        Ok(s) => ExitCode::from(s.code().unwrap_or(1).clamp(0, 255) as u8),
        Err(e) => {
            eprintln!("innerwarden: could not run Active Defence CLI: {e}");
            ExitCode::from(1)
        }
    })
}

/// The promo/trial override file: `~/.config/innerwarden/ad-message.txt`.
fn override_file() -> Option<String> {
    let home = std::env::var("HOME").ok()?;
    std::fs::read_to_string(
        std::path::PathBuf::from(home).join(".config/innerwarden/ad-message.txt"),
    )
    .ok()
}

/// Show the Active Defence upsell for a host command not available here; exit 3.
pub fn show_upsell(command: &str) -> ExitCode {
    print!(
        "{}",
        crate::upsell::message(
            &crate::prog(),
            command,
            |k| std::env::var(k).ok(),
            override_file
        )
    );
    ExitCode::from(3)
}

/// `innerwarden host <verb> [args]` - always run the Active Defence verb.
///
/// The escape hatch for the overlap: without it, a verb both layers implement is
/// answered here and the host one cannot be reached at all.
pub fn cmd_host(rest: &[String]) -> ExitCode {
    // `--help` is a request for usage, not a verb to forward. Delegating it
    // produced "there is no host layer to run `--help` in", which is nonsense.
    let asked_for_help = rest
        .first()
        .is_some_and(|a| a == "--help" || a == "-h" || a == "help");
    let Some(verb) = rest.first().filter(|_| !asked_for_help) else {
        eprintln!("innerwarden host <command> [args]");
        eprintln!("  Runs a command in the Active Defence host layer.");
        eprintln!("  Use it to reach a host command whose name this binary also has:");
        eprintln!("    {}", SHARED_VERBS.join(", "));
        return if asked_for_help {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        };
    };
    if find_ad_cli().is_none() {
        eprintln!(
            "innerwarden host: Active Defence is not installed on this machine, so there is no \
             host layer to run `{verb}` in."
        );
        eprintln!("  → https://innerwarden.com/defend");
        return ExitCode::from(1);
    }
    try_delegate(verb, &rest[1..]).unwrap_or_else(|| {
        eprintln!("innerwarden host: could not run the Active Defence CLI");
        ExitCode::from(1)
    })
}

#[cfg(test)]
mod shared_verb_tests {
    use super::*;

    /// REGRESSION ANCHOR. Delegation only fires for verbs this binary does not
    /// know, so a verb both layers implement was answered here and the host one
    /// was unreachable by any spelling. The overlap must be named, not implied
    /// by match order.
    ///
    /// FAILS ON REVERT: empty the list and the membership checks trip.
    #[test]
    fn the_overlapping_verbs_are_named() {
        for v in ["setup", "dashboard", "upgrade", "uninstall"] {
            assert!(is_shared_verb(v), "`{v}` exists in both layers");
        }
        assert!(!is_shared_verb("check"), "check is ours alone");
        assert!(!is_shared_verb("exec-gate"), "exec-gate is theirs alone");
    }

    /// A machine without Active Defence must never be told about a command it
    /// does not have.
    #[test]
    fn no_hint_is_offered_when_the_host_layer_is_absent() {
        if find_ad_cli().is_some() {
            return; // this machine has it; the other case is covered below
        }
        assert_eq!(shared_verb_hint("setup"), None);
    }

    /// A verb that is ours alone never gets a host hint, whatever is installed.
    #[test]
    fn an_exclusive_verb_never_points_at_the_host_layer() {
        assert_eq!(shared_verb_hint("check"), None);
        assert_eq!(shared_verb_hint("proxy"), None);
    }
}

#[cfg(test)]
mod host_help_tests {
    use super::*;

    /// `--help` is a request for usage, not a verb to forward. Delegating it
    /// produced "there is no host layer to run `--help` in", which is nonsense
    /// and, on a machine WITH Active Defence, would have run `innerwarden-ctl
    /// --help` instead of explaining this command.
    #[test]
    fn help_is_usage_and_not_a_verb_to_delegate() {
        for flag in ["--help", "-h", "help"] {
            let code = cmd_host(&[flag.to_string()]);
            assert_eq!(
                format!("{code:?}"),
                format!("{:?}", ExitCode::SUCCESS),
                "`host {flag}` must succeed with usage"
            );
        }
    }

    /// No arguments at all is a usage ERROR, so a script that forgot the verb
    /// fails rather than looking like it worked.
    #[test]
    fn a_missing_verb_is_still_an_error() {
        let code = cmd_host(&[]);
        assert_ne!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "a missing verb must not exit 0"
        );
    }
}
