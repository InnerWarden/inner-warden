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
