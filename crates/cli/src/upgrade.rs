//! `innerwarden upgrade` - update the Community binary in place to the latest
//! signed release.
//!
//! It reuses the official installer rather than reimplementing download and
//! verification: the installer selects the signed release for this OS/arch,
//! checks its SHA-256, and verifies its Ed25519 signature against a public key
//! pinned inside the installer. Doing the update any other way would be a weaker
//! trust path than a fresh install, so `upgrade` deliberately runs the same
//! verified installer, pointed at wherever this binary already lives.

use std::process::{Command, ExitCode};

const INSTALLER_SH: &str = "https://innerwarden.com/free";
const INSTALLER_PS1: &str = "https://innerwarden.com/free.ps1";

pub fn cmd(rest: &[String]) -> ExitCode {
    if rest.iter().any(|a| a == "--help" || a == "-h") {
        println!("innerwarden upgrade");
        println!(
            "  Update the InnerWarden Community binary in place to the latest signed release."
        );
        println!("  Downloads the official installer, which verifies the SHA-256 and the Ed25519");
        println!("  signature before replacing the binary. Hooks and config are left untouched.");
        return ExitCode::SUCCESS;
    }

    let current = env!("CARGO_PKG_VERSION");
    // Keep the update in the same directory as the running binary, so a
    // `~/.local/bin` install upgrades there and never lands somewhere new.
    let install_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));

    println!("InnerWarden Community {current}: fetching the latest signed release...");

    let script = match fetch(if cfg!(windows) {
        INSTALLER_PS1
    } else {
        INSTALLER_SH
    }) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("innerwarden upgrade: could not fetch the installer: {e}");
            eprintln!(
                "  Check your connection, or reinstall manually from https://innerwarden.com/free"
            );
            return ExitCode::from(1);
        }
    };

    let tmp = std::env::temp_dir().join(if cfg!(windows) {
        "innerwarden-upgrade.ps1"
    } else {
        "innerwarden-upgrade.sh"
    });
    if let Err(e) = std::fs::write(&tmp, script.as_bytes()) {
        eprintln!("innerwarden upgrade: could not stage the installer: {e}");
        return ExitCode::from(1);
    }

    let mut command = if cfg!(windows) {
        let mut c = Command::new("powershell");
        c.args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
            .arg(&tmp);
        c
    } else {
        let mut c = Command::new("sh");
        c.arg(&tmp);
        c
    };
    // The installer honours these: reuse the current location and do not touch
    // the agent hook wiring during an upgrade.
    if let Some(dir) = &install_dir {
        command.env("IW_GUARD_DIR", dir);
    }
    command.env("IW_GUARD_NO_HOOK", "1");

    let status = command.status();
    let _ = std::fs::remove_file(&tmp);

    match status {
        Ok(s) if s.success() => {
            println!();
            println!("Upgrade complete. Confirm with:  innerwarden --version");
            ExitCode::SUCCESS
        }
        Ok(s) => {
            eprintln!(
                "innerwarden upgrade: the installer exited with status {}",
                s.code().unwrap_or(-1)
            );
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("innerwarden upgrade: could not run the installer: {e}");
            ExitCode::from(1)
        }
    }
}

/// Fetch a small text resource over HTTPS (rustls, same client the notifier uses).
fn fetch(url: &str) -> Result<String, String> {
    match ureq::get(url).call() {
        Ok(resp) => resp.into_string().map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    }
}
