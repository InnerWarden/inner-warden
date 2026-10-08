//! Thin I/O for the Active Defence gate: find + delegate to the licensed host CLI when
//! it is installed, otherwise print the (overridable) upsell. All wording + the
//! host-command set live in the pure `upsell` module. Excluded from the coverage
//! floor like the other `_io` adapters.

use std::process::ExitCode;

/// The Active Defence host CLI's file name. Its presence on disk is the
/// product's definition of "Active Defence is installed on this machine".
const AD_CLI_NAME: &str = "innerwarden-ctl";

/// Standard install dirs searched when `PATH` does not name one. These are the
/// directories the installer writes to; a change there changes this.
const AD_INSTALL_DIRS: [&str; 3] = ["/usr/local/bin", "/usr/bin", "/opt/innerwarden/bin"];

/// Search `dirs`, in order, for the Active Defence host CLI.
///
/// Split from [`find_ad_cli`] so the search itself is testable against a
/// directory the test controls. A single function that reads absolute paths and
/// decides in one step can only be asserted against whatever happens to be
/// installed on the machine running the test: nothing on a laptop, something
/// else in CI, and a test that would pass just as happily against a body that
/// always answered `None`.
fn find_ad_cli_in<I>(dirs: I) -> Option<std::path::PathBuf>
where
    I: IntoIterator<Item = std::path::PathBuf>,
{
    dirs.into_iter()
        .map(|dir| dir.join(AD_CLI_NAME))
        .find(|p| p.is_file())
}

/// A PATH-style list that REPLACES every place the host CLI is looked for
/// (`PATH` and [`AD_INSTALL_DIRS`]); set and empty, nothing is searched.
///
/// Why it exists: the standard dirs are absolute, so this binary's own tests
/// could not be isolated from the machine running them. On a host with Active
/// Defence in `/usr/local/bin`, `innerwarden statsu` and `get --help` were
/// delegated to the real `innerwarden-ctl` and two test files failed for a
/// reason that had nothing to do with the code.
///
/// Not a trust boundary: `PATH`, which the same caller controls, is already
/// searched first, so this lets a caller choose nothing it could not before.
pub const AD_CLI_DIRS_ENV: &str = "IW_AD_CLI_DIRS";

/// Where to look for the host CLI, in order. PURE: the environment is handed
/// in, so the override is testable without touching the process environment.
fn ad_cli_search_dirs(
    override_dirs: Option<std::ffi::OsString>,
    path: Option<std::ffi::OsString>,
) -> Vec<std::path::PathBuf> {
    if let Some(dirs) = override_dirs {
        return std::env::split_paths(&dirs)
            .filter(|d| !d.as_os_str().is_empty())
            .collect();
    }
    path.map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .chain(AD_INSTALL_DIRS.iter().map(std::path::PathBuf::from))
        .collect()
}

/// Locate the Active Defence host CLI (`innerwarden-ctl`) if it is installed: on
/// PATH, or in a standard install dir (or only where [`AD_CLI_DIRS_ENV`] says).
/// Its presence is how the Community binary knows Active Defence is on this
/// machine.
fn find_ad_cli() -> Option<std::path::PathBuf> {
    find_ad_cli_in(ad_cli_search_dirs(
        std::env::var_os(AD_CLI_DIRS_ENV),
        std::env::var_os("PATH"),
    ))
}

/// The second line `innerwarden --version` prints, on stderr, when the host
/// stack is installed. `innerwarden --version` is the FREE CLI's release, and
/// the install docs once told paid operators it confirmed the release they
/// had installed. stderr, so every script that reads the version from stdout
/// still reads exactly one line.
pub fn version_host_hint(ad_installed: bool) -> Option<&'static str> {
    ad_installed.then_some(
        "Active Defence is installed here; its host stack has its own release: innerwarden-ctl --version",
    )
}

/// Whether the paid Active Defence host stack is INSTALLED on this machine.
///
/// Public because the dashboard needs this same answer. Its Overview closes
/// with a card offering Active Defence, and on a host already running it that
/// card told the operator to go and buy what was already underneath them --
/// beneath a header reading "Setup needed", so the honest reading of the screen
/// was "you are not protected". Sharing one definition is the point: a second
/// detector written for the dashboard could disagree with the delegation path
/// about the very same host.
///
/// INSTALLED, never ARMED. A binary on disk proves someone installed it and
/// nothing more. Whether a kernel guard is actually armed lives in `LSM_POLICY`,
/// takes root to read, and this dashboard runs unprivileged. No caller may
/// promote this answer into a claim about protection.
pub fn active_defence_installed() -> bool {
    find_ad_cli().is_some()
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
    // `help` is a request for usage, not a verb to forward. Delegating it
    // produced "there is no host layer to run `help` in", which is nonsense.
    // The `--help` / `-h` spellings are answered before dispatch, in
    // `help::for_invocation`.
    let asked_for_help = rest.first().is_some_and(|a| a == "help");
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
    ///
    /// The two flag spellings are now answered before dispatch, so they are
    /// asserted where that decision lives; the bare word still lands here.
    #[test]
    fn help_is_usage_and_not_a_verb_to_delegate() {
        for flag in ["--help", "-h"] {
            assert!(
                crate::help::for_invocation("host", &[flag.to_string()]).is_some(),
                "`host {flag}` must be answered with usage, never delegated"
            );
        }
        let code = cmd_host(&["help".to_string()]);
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "`host help` must succeed with usage"
        );
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

#[cfg(test)]
mod active_defence_detection_tests {
    use super::*;
    use std::path::PathBuf;

    /// THE DEFECT THIS PINS
    ///
    /// The Community dashboard's Overview ends with a card headed "Extend
    /// protection from agent intent to the host." It rendered unconditionally
    /// for the Community edition, so on `iw-challenge` -- a box running the
    /// sensor, the watchdog, the DNS guard, an armed Execution Gate with 1387
    /// entries and a Secret Read Guard in ENFORCE -- the dashboard invited the
    /// operator to go and acquire what was already running underneath it.
    ///
    /// The dashboard now asks this module instead of guessing, so the search
    /// has to actually find a real file and actually miss when there is none.
    fn touch(dir: &std::path::Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, b"#!/bin/sh\n").expect("write the fake binary");
        p
    }

    /// The override replaces BOTH `PATH` and the absolute install dirs: the
    /// absolute dirs are what made this binary's tests fail on a machine with
    /// Active Defence in `/usr/local/bin`.
    ///
    /// FAILS ON REVERT (the override ignored): the search still names
    /// `/usr/local/bin` and the `PATH` entry.
    #[test]
    fn the_override_replaces_path_and_the_install_dirs() {
        let only = ad_cli_search_dirs(Some("/x/a:/x/b".into()), Some("/on/path".into()));
        assert_eq!(only, vec![PathBuf::from("/x/a"), PathBuf::from("/x/b")]);
        let none = ad_cli_search_dirs(Some("".into()), Some("/on/path".into()));
        assert!(none.is_empty(), "set and empty searches nowhere: {none:?}");
        let default = ad_cli_search_dirs(None, Some("/on/path".into()));
        assert_eq!(default.first(), Some(&PathBuf::from("/on/path")));
        for d in AD_INSTALL_DIRS {
            assert!(
                default.contains(&PathBuf::from(d)),
                "{d} searched by default"
            );
        }
    }

    /// `innerwarden --version` names the FREE release; with the host stack
    /// installed it says where the paid release is read, and without it says
    /// nothing about a product that is not there.
    #[test]
    fn the_version_points_at_the_host_release_only_when_it_is_installed() {
        let hint = version_host_hint(true).expect("installed: a hint");
        assert!(hint.contains("innerwarden-ctl --version"), "{hint}");
        assert_eq!(version_host_hint(false), None);
    }

    #[test]
    fn the_host_cli_is_found_where_it_is_installed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let expected = touch(dir.path(), AD_CLI_NAME);
        assert_eq!(
            find_ad_cli_in([dir.path().to_path_buf()]),
            Some(expected),
            "a directory containing {AD_CLI_NAME} means Active Defence is installed"
        );
    }

    /// The other half, and the one that keeps the test above honest: a body
    /// that always answered `Some(..)` would pass the first assertion alone.
    #[test]
    fn an_empty_directory_is_not_an_installation() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            find_ad_cli_in([dir.path().to_path_buf()]),
            None,
            "nothing on disk must not read as an installation"
        );
    }

    /// A NEIGHBOUR is not the host CLI. The Community binary is named
    /// `innerwarden`, and it lives in exactly the directories searched here --
    /// so a match on the wrong name would report Active Defence installed on
    /// every Community host in existence, which is the defect inverted.
    #[test]
    fn the_community_binary_is_not_mistaken_for_the_host_cli() {
        let dir = tempfile::tempdir().expect("tempdir");
        touch(dir.path(), "innerwarden");
        touch(dir.path(), "innerwarden-guard");
        assert_eq!(
            find_ad_cli_in([dir.path().to_path_buf()]),
            None,
            "only {AD_CLI_NAME} counts; the Community binary sits in the same dirs"
        );
    }

    /// Directories are searched in order and a miss does not stop the search.
    /// The real caller chains PATH ahead of the standard install dirs, so an
    /// early empty entry must not shadow a later real one.
    #[test]
    fn the_search_continues_past_directories_that_do_not_have_it() {
        let empty = tempfile::tempdir().expect("tempdir");
        let real = tempfile::tempdir().expect("tempdir");
        let expected = touch(real.path(), AD_CLI_NAME);
        assert_eq!(
            find_ad_cli_in([empty.path().to_path_buf(), real.path().to_path_buf()]),
            Some(expected),
            "an earlier directory without it must not end the search"
        );
    }

    /// A path that does not exist at all is a miss, not a panic. `PATH`
    /// routinely names directories that are not there.
    #[test]
    fn a_directory_that_does_not_exist_is_survived() {
        assert_eq!(
            find_ad_cli_in([PathBuf::from("/nonexistent-innerwarden-test-dir")]),
            None
        );
    }

    /// A directory NAMED like the binary is not a binary. `is_file` is what
    /// makes this true; `exists` would not.
    #[test]
    fn a_directory_with_the_cli_name_is_not_an_installation() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join(AD_CLI_NAME)).expect("create the decoy dir");
        assert_eq!(find_ad_cli_in([dir.path().to_path_buf()]), None);
    }

    /// The public predicate is the one the dashboard calls, and it must agree
    /// with the delegation path on the same host. Asserting agreement rather
    /// than a fixed value is deliberate: the answer depends on the machine
    /// running the test, so pinning `true` or `false` would make this either a
    /// laptop test or a CI test and never both.
    #[test]
    fn the_public_predicate_agrees_with_the_delegation_path() {
        assert_eq!(active_defence_installed(), find_ad_cli().is_some());
    }
}
