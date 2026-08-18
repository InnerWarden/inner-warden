//! `innerwarden upgrade` - update the Community binary in place to the latest
//! signed release.
//!
//! # Why it no longer runs the installer (audit SEC-01)
//!
//! This used to fetch `https://innerwarden.com/free` and pipe it to `sh`, on the
//! reasoning that reusing the official installer was a stronger trust path than
//! reimplementing verification. The reasoning had a hole: the Ed25519 pin the
//! installer checks against lives INSIDE the installer. The trust anchor
//! travelled with the artifact it was meant to authenticate, so whoever could
//! serve the script could serve its key too, and the check passed either way.
//!
//! The already-installed binary is the better anchor: it is on disk because a
//! human put it there, and it can carry the key. So the update now downloads the
//! release asset and its two sidecars and verifies them against the key compiled
//! into THIS binary. Nothing downloaded is executed in order to decide whether
//! what was downloaded can be trusted.

use std::io::Read as _;
use std::path::Path;
use std::process::ExitCode;

use crate::release_verify;
use crate::upgrade_plan;

/// Cap on a downloaded artifact. Generous against the real binaries (single
/// digit MB) and bounded so a hostile or broken endpoint cannot stream until the
/// machine runs out of memory.
const MAX_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024;

pub fn cmd(rest: &[String]) -> ExitCode {
    if rest.iter().any(|a| a == "--help" || a == "-h") {
        println!("innerwarden upgrade");
        println!(
            "  Update the InnerWarden Community binary in place to the latest signed release."
        );
        println!("  Downloads the release asset and verifies its SHA-256 and Ed25519 signature");
        println!("  against the key compiled into this binary before replacing anything.");
        println!("  Hooks and config are left untouched.");
        return ExitCode::SUCCESS;
    }

    let current = env!("CARGO_PKG_VERSION");
    let Some(asset) = upgrade_plan::asset_for_this_host() else {
        eprintln!(
            "innerwarden upgrade: no published build for {}/{}.",
            std::env::consts::OS,
            std::env::consts::ARCH
        );
        return ExitCode::from(1);
    };
    let Ok(target) = std::env::current_exe() else {
        eprintln!("innerwarden upgrade: could not locate the running binary.");
        return ExitCode::from(1);
    };

    println!("InnerWarden Community {current}: fetching {asset}...");
    let (bin_url, sha_url, sig_url) = upgrade_plan::urls_for(&asset);

    let bytes = match fetch_bytes(&bin_url) {
        Ok(b) => b,
        Err(e) => return fail(&format!("could not download the release: {e}")),
    };
    let sha = match fetch_text(&sha_url) {
        Ok(s) => s,
        Err(e) => return fail(&format!("could not download the SHA-256 sidecar: {e}")),
    };
    let sig = match fetch_text(&sig_url) {
        Ok(s) => s,
        Err(e) => return fail(&format!("could not download the signature: {e}")),
    };

    if let Err(e) = release_verify::verify_release(&bytes, &sha, &sig) {
        eprintln!("innerwarden upgrade: REFUSED, {e}.");
        eprintln!("  Nothing was changed. The installed binary is untouched.");
        return ExitCode::from(1);
    }
    println!("Signature verified against this build\'s pinned release key.");

    match install_verified(&target, &bytes) {
        Ok(()) => {
            println!();
            println!("Upgrade complete. Confirm with:  innerwarden --version");
            for line in closing_advice(dashboard_is_serving()) {
                println!("{line}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => fail(&format!("verified, but could not replace the binary: {e}")),
    }
}

/// Is something answering on the dashboard's default address right now?
///
/// Probed rather than assumed, and only the default bind is checked: an
/// operator who moved it knows they did, and guessing at ports would be slower
/// and no more correct. A short timeout, and any error means "no" — a failed
/// probe must never turn a successful upgrade into a scary ending.
fn dashboard_is_serving() -> bool {
    ureq::get("http://127.0.0.1:8787/api/guard/meta")
        .timeout(std::time::Duration::from_millis(400))
        .call()
        .is_ok()
}

/// What to print after a successful replace.
///
/// `innerwarden --version` reads the file on disk, so it reports the NEW
/// version the moment the rename lands. A dashboard that was already running
/// keeps the inode it started with and goes on serving the OLD one. On a real
/// machine those two surfaces disagreed for nine days, and the closing line
/// above sent the operator to the surface that agrees.
///
/// So when something is answering on the dashboard's address, say so here.
/// Pure, because the wording is the part worth pinning.
fn closing_advice(dashboard_running: bool) -> Vec<String> {
    if !dashboard_running {
        return Vec::new();
    }
    vec![
        String::new(),
        "A dashboard is running on 127.0.0.1:8787 and is still executing the".into(),
        "previous binary: replacing a file does not change a process already".into(),
        "running it. Restart the dashboard to serve this version.".into(),
        "  (Its page will say so too, until you do.)".into(),
    ]
}

fn fail(message: &str) -> ExitCode {
    eprintln!("innerwarden upgrade: {message}");
    ExitCode::from(1)
}

/// Write the verified bytes beside the target and rename over it.
///
/// The rename is the last step and is atomic on the same filesystem, so an
/// interrupted upgrade leaves either the old binary or the new one, never a
/// half-written file that still has the execute bit.
fn install_verified(target: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let staged = upgrade_plan::staging_path(target);
    std::fs::write(&staged, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))?;
    }
    match std::fs::rename(&staged, target) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&staged);
            Err(e)
        }
    }
}

/// Download a binary artifact, bounded.
fn fetch_bytes(url: &str) -> Result<Vec<u8>, String> {
    let resp = ureq::get(url).call().map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    resp.into_reader()
        .take(MAX_ARTIFACT_BYTES)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    if buf.is_empty() {
        return Err("empty response".into());
    }
    Ok(buf)
}

/// Fetch a small text sidecar over HTTPS.
fn fetch_text(url: &str) -> Result<String, String> {
    ureq::get(url)
        .call()
        .map_err(|e| e.to_string())?
        .into_string()
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REGRESSION ANCHOR for SEC-01. The updater must not fetch a script and run
    /// it: that is what put the trust anchor inside the artifact. This asserts
    /// against the module source, so reintroducing the pattern fails here.
    #[test]
    fn the_updater_never_downloads_and_executes_a_script() {
        let src = include_str!("upgrade.rs");
        // Scan CODE only. The module header deliberately names the old URL to
        // explain why it is gone, and a prose mention is not a code path.
        let body: String = src
            .split("mod tests")
            .next()
            .unwrap_or(src)
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !t.starts_with("//!") && !t.starts_with("///") && !t.starts_with("//")
            })
            .collect::<Vec<_>>()
            .join("\n");
        for banned in [
            "ExecutionPolicy",
            "Command::new(\"sh\")",
            "innerwarden.com/free",
        ] {
            assert!(
                !body.contains(banned),
                "the updater must not reintroduce `{banned}`: verification would move back into the downloaded artifact"
            );
        }
        assert!(
            body.contains("release_verify::verify_release"),
            "the updater must verify against the compiled-in key"
        );
    }

    /// The verified bytes are written to a staging path and renamed; the target
    /// is never opened for writing before verification.
    #[test]
    fn the_target_is_replaced_by_an_atomic_rename() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("innerwarden");
        std::fs::write(&target, b"old binary").expect("seed");

        install_verified(&target, b"new binary").expect("install");

        assert_eq!(std::fs::read(&target).unwrap(), b"new binary");
        assert!(
            !upgrade_plan::staging_path(&target).exists(),
            "the staging file must not survive a successful upgrade"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&target).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755, "the replacement must be executable");
        }
    }

    /// A failed replace must not leave a stray staging file behind that a later
    /// run, or a curious operator, could mistake for a binary.
    #[test]
    fn a_failed_replace_cleans_up_after_itself() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A directory as the target makes the rename fail without needing a
        // permission trick that differs between CI and a developer machine.
        let target = dir.path().join("innerwarden");
        std::fs::create_dir(&target).expect("target as a directory");

        let result = install_verified(&target, b"new binary");
        assert!(result.is_err(), "renaming onto a directory must fail");
        assert!(
            !upgrade_plan::staging_path(&target).exists(),
            "the staging file must be removed when the rename fails"
        );
    }
}

#[cfg(test)]
mod closing_advice_tests {
    use super::closing_advice;

    /// Nothing listening: the upgrade ends exactly as it always did. A notice
    /// about a dashboard that is not running would be noise, and noise in a
    /// success path is how people learn to skim past the line that matters.
    #[test]
    fn a_quiet_host_gets_no_extra_words() {
        assert!(closing_advice(false).is_empty());
    }

    /// The production case: a dashboard was left running for nine days, an
    /// upgrade renamed a new binary over the old one, and the page went on
    /// serving 1.3.0 while `--version` said 1.3.3. The upgrade's own closing
    /// line pointed at the surface that agreed.
    #[test]
    fn a_running_dashboard_is_named_with_what_to_do_about_it() {
        let advice = closing_advice(true).join("\n");
        assert!(
            advice.contains("127.0.0.1:8787"),
            "name where it is, so the operator does not have to hunt"
        );
        assert!(
            advice.to_lowercase().contains("restart"),
            "say what to do, not merely that something is stale"
        );
        assert!(
            advice.to_lowercase().contains("previous binary"),
            "say WHY, or it reads as a superstition about restarting things"
        );
    }
}
