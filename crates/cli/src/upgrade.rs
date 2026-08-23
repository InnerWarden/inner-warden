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

/// What an invocation of `upgrade` was asked to do.
///
/// Extracted from `cmd` so the refusal is a value a test can hold, rather than a
/// side effect a test can only infer. The previous test for this asserted the
/// ORDER OF SUBSTRINGS IN THIS FILE'S OWN SOURCE ("unknown option" appears
/// before "fetching {asset}"), which is true of a file that never runs and says
/// nothing about what an unknown flag does.
///
/// That mattered here more than most places: `upgrade --check` performed a real
/// upgrade on a live host on 2026-08-21. The least-tested critical path had
/// already shipped the defect its tests were supposed to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invocation {
    /// Refuse: the flag was not understood. Carries the offending argument.
    ///
    /// A mutating command must not silently ignore what it was asked. The
    /// failure mode of guessing wrong on THIS command is replacing the running
    /// binary.
    Refuse(String),
    /// Report whether an upgrade exists and change nothing.
    Check,
    /// Download, verify, and replace.
    ///
    /// `forced` carries `--yes`/`-y`, which until now was accepted and did
    /// nothing at all. It is the acknowledgement that overrides the npm refusal
    /// below, and nothing else: it does not skip verification, and it cannot
    /// turn a `--check` into an install.
    Upgrade { forced: bool },
}

/// Usage for `innerwarden upgrade`, named as it was invoked (`update` and
/// `self-update` reach the same code). Printed by `help::for_invocation` before
/// dispatch, so this command never has to recognise a help flag itself.
pub(crate) fn help_text(verb: &str) -> String {
    let p = crate::prog();
    format!(
        "{p} {verb} [--check] [--yes]\n  \
         Update the InnerWarden Community binary in place to the latest signed\n  \
         release. It downloads the release asset and verifies its SHA-256 and its\n  \
         Ed25519 signature against the key compiled into this binary before replacing\n  \
         anything. Hooks and config are left untouched.\n\
         \n  \
         --check   report which version is published, and change nothing\n  \
         --yes     replace an npm-managed copy anyway (see the refusal for why not)"
    )
}

/// Pure: what the arguments ask for.
///
/// There is no `Help` here: usage is answered in `main` before dispatch (see
/// `help::for_invocation`), so a help flag cannot arrive. If one ever did it
/// would be refused as the unknown option it is, which downloads nothing and
/// leaves the running binary alone.
pub fn plan_invocation(rest: &[String]) -> Invocation {
    if let Some(bad) = rest
        .iter()
        .find(|a| a.starts_with('-') && *a != "--check" && *a != "--yes" && *a != "-y")
    {
        return Invocation::Refuse(bad.clone());
    }
    if rest.iter().any(|a| a == "--check") {
        return Invocation::Check;
    }
    Invocation::Upgrade {
        forced: rest.iter().any(|a| a == "--yes" || a == "-y"),
    }
}

pub fn cmd(rest: &[String]) -> ExitCode {
    let invocation = plan_invocation(rest);

    // A mutating command must not silently ignore what it was asked to do.
    //
    // Only `--help` was recognised; every other flag fell through and the
    // binary was replaced anyway. `innerwarden upgrade --check` is the obvious
    // thing to type, it is exactly the flag the PAID CLI supports
    // (`innerwarden-ctl upgrade --check` reports and exits), and here it
    // performed the upgrade. Found on a live host 2026-08-21 while trying to
    // check whether an upgrade was available: it upgraded.
    //
    // Unknown flags are now refused rather than ignored, because the failure
    // mode of guessing wrong on THIS command is replacing the running binary.
    if let Invocation::Refuse(bad) = &invocation {
        eprintln!("innerwarden upgrade: unknown option {bad}.");
        eprintln!("  Nothing was downloaded. The installed binary is untouched.");
        eprintln!("  Try: innerwarden upgrade [--check]");
        return ExitCode::from(2);
    }
    let check_only = invocation == Invocation::Check;
    let forced = invocation == Invocation::Upgrade { forced: true };

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

    // An npm-managed copy must not be replaced by hand, and that has to be said
    // BEFORE the download rather than after a failure.
    //
    // `upgrade_plan` already documented this hazard and `managed_by` already
    // detected it, but both callers were on the FAILURE path: the warning only
    // ever appeared when the replace had ALSO failed, which happens when npm's
    // prefix is root-owned. Under `npm config set prefix ~/.npm-global`, which
    // is exactly what the install page recommends, the prefix is user-owned, so
    // the replace SUCCEEDS. The user is told "Upgrade complete", npm goes on
    // believing it ships the old version, and the next `npm install -g` silently
    // puts the old binary back. The only case the advice existed for was the one
    // case it was never shown in.
    if upgrade_plan::npm_refusal_applies(&target, check_only, forced) {
        eprintln!("innerwarden upgrade: REFUSED, this copy is managed by npm.");
        eprintln!("  Nothing was downloaded. The installed binary is untouched.");
        eprintln!();
        for line in upgrade_plan::cannot_replace_advice(&target, running_as_root()) {
            eprintln!("{line}");
        }
        eprintln!();
        eprintln!("  To replace npm's file anyway, knowing the next `npm install -g`");
        eprintln!("  will undo it:  innerwarden upgrade --yes");
        return ExitCode::from(2);
    }

    // Prove we can replace the binary BEFORE downloading it.
    //
    // The check used to happen implicitly, at the rename, after the download
    // and both signature checks had already run. Someone whose CLI came from
    // `npm install -g` therefore waited through the whole verified download to
    // be told "could not replace the binary: Permission denied", with no
    // indication that the fix is npm rather than sudo. Fail in the first second
    // instead, and say which command to run.
    if let Err(e) = can_replace(&target) {
        eprintln!("innerwarden upgrade: cannot replace the installed binary ({e}).");
        eprintln!("  Nothing was downloaded. The installed binary is untouched.");
        eprintln!();
        for line in upgrade_plan::cannot_replace_advice(&target, running_as_root()) {
            eprintln!("{line}");
        }
        return ExitCode::from(1);
    }

    if check_only {
        // Report, change nothing.
        //
        // This used to fetch the small `.sha256` sidecar, DISCARD it, and print
        // "Run `innerwarden upgrade` to install it" on any HTTP success. It said
        // that on 1.3.7 while 1.3.7 was the published release, because a
        // reachable sidecar says only that a release exists, never which one. So
        // it answered "yes, upgrade" to every host that could reach GitHub, and
        // a check that cannot say "no" answers nothing.
        //
        // The published version is named in the manifest the release workflow
        // generates from the built binary's own `--version` and uploads beside
        // the binaries, so compare against that. Still small, still no binary
        // download.
        let manifest_url = upgrade_plan::manifest_url_from(upgrade_plan::RELEASE_BASE);
        let manifest = match fetch_text(&manifest_url) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("innerwarden upgrade --check: could not reach the release ({e}).");
                eprintln!("  Nothing was downloaded. The installed binary is untouched.");
                return ExitCode::from(1);
            }
        };
        let outcome = upgrade_plan::check_outcome(current, &manifest);
        for line in upgrade_plan::check_lines(&outcome, &asset, upgrade_plan::managed_by(&target)) {
            println!("{line}");
        }
        // "Could not tell" is not success. Exiting 0 there would let a script
        // treat an unanswerable check as a clean bill of health.
        return match outcome {
            upgrade_plan::CheckOutcome::Undetermined => ExitCode::from(1),
            _ => ExitCode::SUCCESS,
        };
    }

    println!("InnerWarden Community {current}: fetching {asset}...");

    // One implementation, shared with the tests. Before this the download,
    // verification and install lived inline here, so the only way to test them
    // was to assert the order of substrings in this file, and that is how
    // `upgrade --check` shipped performing a real upgrade.
    match fetch_verify_install(upgrade_plan::RELEASE_BASE, &asset, &target) {
        FetchOutcome::Installed => {
            println!("Signature verified against this build's pinned release key.");
            println!();
            println!("Upgrade complete. Confirm with:  innerwarden --version");
            for line in closing_advice(dashboard_is_serving()) {
                println!("{line}");
            }
            ExitCode::SUCCESS
        }
        FetchOutcome::DownloadFailed(what) => fail(&format!("could not download the {what}")),
        FetchOutcome::VerificationFailed(why) => {
            eprintln!("innerwarden upgrade: REFUSED, {why}.");
            eprintln!("  Nothing was changed. The installed binary is untouched.");
            ExitCode::from(1)
        }
        FetchOutcome::InstallFailed(e) => {
            eprintln!("innerwarden upgrade: verified, but could not replace the binary: {e}");
            eprintln!();
            for line in upgrade_plan::cannot_replace_advice(&target, running_as_root()) {
                eprintln!("{line}");
            }
            ExitCode::from(1)
        }
    }
}

/// Can the binary actually be replaced, right now, by this user?
///
/// Writing and removing the real staging file is the honest test: it exercises
/// the same directory, the same filename, and the same permissions the upgrade
/// will use. Inspecting the mode bits instead would guess, and would guess
/// wrong under a read-only mount, an immutable flag, or a full disk.
fn can_replace(target: &Path) -> std::io::Result<()> {
    let staged = upgrade_plan::staging_path(target);
    std::fs::write(&staged, b"")?;
    std::fs::remove_file(&staged)
}

#[cfg(unix)]
fn running_as_root() -> bool {
    // getuid takes no arguments, touches no memory, and cannot fail.
    unsafe { libc::getuid() == 0 }
}

#[cfg(not(unix))]
fn running_as_root() -> bool {
    false
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
/// What a download-and-install attempt did.
///
/// Returned rather than printed so a test can assert on the OUTCOME. The
/// previous tests for this path asserted the order of substrings in this file's
/// own source, which is how `upgrade --check` shipped performing a real upgrade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchOutcome {
    /// Bytes arrived, verified against the pinned key, and replaced the target.
    Installed,
    /// Something could not be downloaded. Nothing was written.
    DownloadFailed(String),
    /// Bytes arrived and did not verify. Nothing was written.
    VerificationFailed(String),
    /// Verified, but the replacement itself failed. The previous binary is
    /// still in place, because the staged file is renamed over the target and
    /// a failed rename removes the staging file rather than the target.
    InstallFailed(String),
}

/// Download an asset from `base`, verify it, and replace `target`.
///
/// `base` is a parameter so the whole path can be driven against a local
/// server. Production passes the release base and nothing else does.
///
/// Verification uses the production `release_verify::verify_release`, so a test
/// that feeds this corrupted bytes or a foreign signature is exercising the code
/// compiled into the shipped binary rather than a copy of it.
pub fn fetch_verify_install(base: &str, asset: &str, target: &Path) -> FetchOutcome {
    let (bin_url, sha_url, sig_url) = upgrade_plan::urls_from(base, asset);

    let bytes = match fetch_bytes(&bin_url) {
        Ok(b) => b,
        Err(e) => return FetchOutcome::DownloadFailed(format!("release: {e}")),
    };
    let sha = match fetch_text(&sha_url) {
        Ok(t) => t,
        Err(e) => return FetchOutcome::DownloadFailed(format!("sha256 sidecar: {e}")),
    };
    let sig = match fetch_text(&sig_url) {
        Ok(t) => t,
        Err(e) => return FetchOutcome::DownloadFailed(format!("signature: {e}")),
    };

    if let Err(e) = release_verify::verify_release(&bytes, &sha, &sig) {
        return FetchOutcome::VerificationFailed(format!("{e:?}"));
    }
    match install_verified(target, &bytes) {
        Ok(()) => FetchOutcome::Installed,
        Err(e) => FetchOutcome::InstallFailed(e.to_string()),
    }
}

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
    /// An unknown flag refuses, and refuses BEFORE anything is fetched.
    ///
    /// The previous version of this test asserted the order of substrings in
    /// this file's own source: that "unknown option" appeared before
    /// "fetching {asset}". That is true of a file that never runs. It passed on
    /// every tree this repo has ever had, including the tree where
    /// `upgrade --check` performed a real upgrade on a live host on 2026-08-21.
    ///
    /// FAILS ON REVERT: let an unrecognised flag fall through to `Upgrade`.
    #[test]
    fn an_unknown_flag_refuses_instead_of_upgrading() {
        for bad in ["--force", "--dry-run", "-x", "--checkk"] {
            assert_eq!(
                plan_invocation(&[bad.to_string()]),
                Invocation::Refuse(bad.to_string()),
                "{bad} must be refused, not ignored: the failure mode of guessing \
                 wrong here is replacing the running binary"
            );
        }
    }

    /// `--check` reports and never upgrades.
    ///
    /// This is the defect that shipped. It is now a value, so it cannot be
    /// mistaken for the upgrade path by anything downstream.
    #[test]
    fn check_is_never_an_upgrade() {
        assert_eq!(plan_invocation(&["--check".to_string()]), Invocation::Check);
        assert_eq!(
            plan_invocation(&["--check".to_string(), "--yes".to_string()]),
            Invocation::Check,
            "--yes must not turn a report into an install"
        );
    }

    /// The recognised set, so a flag is not accidentally dropped from it.
    #[test]
    fn the_recognised_flags_behave_as_documented() {
        assert_eq!(plan_invocation(&[]), Invocation::Upgrade { forced: false });
        assert_eq!(
            plan_invocation(&["--yes".to_string()]),
            Invocation::Upgrade { forced: true },
            "--yes is the acknowledgement that overrides the npm refusal"
        );
        assert_eq!(
            plan_invocation(&["-y".to_string()]),
            Invocation::Upgrade { forced: true }
        );
    }

    /// Help wins over a bad flag: `upgrade --help --nonsense` should explain,
    /// not scold. Asking for help is never the dangerous path.
    ///
    /// That decision now lives in `help::for_invocation`, which answers before
    /// dispatch, so this asserts it there and asserts that the flag reaching
    /// this parser anyway would still download nothing.
    #[test]
    fn help_is_answered_before_this_parser_and_refused_if_it_ever_arrived() {
        for verb in ["upgrade", "update", "self-update"] {
            assert!(crate::help::for_invocation(
                verb,
                &["--help".to_string(), "--nonsense".to_string()]
            )
            .is_some());
            assert!(crate::help::for_invocation(verb, &["-h".to_string()]).is_some());
        }
        assert_eq!(
            plan_invocation(&["--help".to_string()]),
            Invocation::Refuse("--help".to_string()),
            "an unrecognised flag on the command that replaces the running binary \
             must be refused, never ignored"
        );
    }

    /// `--check` never reaches the code that replaces the binary.
    ///
    /// This was "structural": it asserted that the substring `if check_only {`
    /// appeared before `fetching {asset}` in this file's own source. It broke
    /// the moment a COMMENT mentioned the second string, which is a fair summary
    /// of what such a test measures. It also passed on the tree where
    /// `upgrade --check` performed a real upgrade on a live host.
    ///
    /// The property is now held by the type: the check path and the upgrade path
    /// are different values, and only one of them reaches
    /// `fetch_verify_install`.
    ///
    /// FAILS ON REVERT: make `plan_invocation` return `Upgrade` for `--check`.
    #[test]
    fn check_only_returns_before_the_binary_is_fetched() {
        let plan = plan_invocation(&["--check".to_string()]);
        assert_eq!(plan, Invocation::Check);
        assert_ne!(
            plan,
            Invocation::Upgrade { forced: false },
            "the only thing between --check and a replaced binary is this \
             distinction, and on 2026-08-21 it did not exist"
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

#[cfg(test)]
mod e2e {
    use super::*;
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;

    /// A release server that answers exactly what it was given and 404s the rest.
    struct FakeRelease {
        base: String,
        port: u16,
        _stop: mpsc::Sender<()>,
    }

    impl Drop for FakeRelease {
        /// Wake the accept loop so its thread can see the closed channel and
        /// return.
        ///
        /// Without this the thread blocks in `incoming()` forever: the stop
        /// channel is only checked after a connection arrives, and none ever
        /// does once the test finishes. A leaked blocked thread per test is
        /// invisible under `cargo test`, which exits the process regardless, and
        /// fatal under coverage instrumentation, which waits for the binary to
        /// come down cleanly and reports `Test failed during run` when it does
        /// not. That is exactly how this first failed in CI.
        fn drop(&mut self) {
            let _ = TcpStream::connect(("127.0.0.1", self.port));
        }
    }

    impl FakeRelease {
        /// Serve `routes` (path without leading slash -> body) until dropped.
        fn serve(routes: HashMap<String, Vec<u8>>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
            let port = listener.local_addr().expect("addr").port();
            let (stop_tx, stop_rx) = mpsc::channel::<()>();

            thread::spawn(move || {
                for incoming in listener.incoming() {
                    // Disconnected means the FakeRelease was dropped: its Drop
                    // opens one connection purely to get us here.
                    if matches!(
                        stop_rx.try_recv(),
                        Ok(()) | Err(mpsc::TryRecvError::Disconnected)
                    ) {
                        return;
                    }
                    let Ok(stream) = incoming else { continue };
                    let _ = answer(stream, &routes);
                }
            });

            Self {
                base: format!("http://127.0.0.1:{port}"),
                port,
                _stop: stop_tx,
            }
        }
    }

    fn answer(mut stream: TcpStream, routes: &HashMap<String, Vec<u8>>) -> std::io::Result<()> {
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut request_line = String::new();
        reader.read_line(&mut request_line)?;
        // Drain headers so the client is not left waiting on a half-read request.
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 || line.trim().is_empty() {
                break;
            }
        }

        let path = request_line
            .split_whitespace()
            .nth(1)
            .unwrap_or("/")
            .trim_start_matches('/')
            .to_string();

        match routes.get(&path) {
            Some(body) => {
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(head.as_bytes())?;
                stream.write_all(body)?;
            }
            None => {
                let body = b"not found";
                let head = format!(
                    "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(head.as_bytes())?;
                stream.write_all(body)?;
            }
        }
        stream.flush()
    }

    // ── release fixtures ────────────────────────────────────────────────────────

    const ASSET: &str = "innerwarden-linux-x86_64";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A release signed by the key the shipped binary actually pins.
    ///
    /// There is no such key available to a test, which is the point: the production
    /// verifier trusts one key and a test cannot forge it. So the "genuine" case
    /// here is asserted through the verifier's own unit tests, and these end-to-end
    /// tests assert the REFUSALS, which is the half that protects a user.
    fn routes_with(bin: &[u8], sha: &str, sig: &str) -> HashMap<String, Vec<u8>> {
        let mut r = HashMap::new();
        r.insert(ASSET.to_string(), bin.to_vec());
        r.insert(format!("{ASSET}.sha256"), sha.as_bytes().to_vec());
        r.insert(format!("{ASSET}.sig"), sig.as_bytes().to_vec());
        r
    }

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("iw-updater-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("tempdir");
        p
    }

    /// An installed binary the upgrade would replace.
    fn existing_binary(dir: &std::path::Path) -> std::path::PathBuf {
        let target = dir.join("innerwarden");
        std::fs::write(&target, b"THE WORKING BINARY").expect("seed the installed binary");
        target
    }

    fn still_intact(target: &std::path::Path) -> bool {
        std::fs::read(target).is_ok_and(|b| b == b"THE WORKING BINARY")
    }

    // ── the tests ───────────────────────────────────────────────────────────────

    /// A binary whose bytes do not match the published digest is refused, and the
    /// installed binary is untouched.
    ///
    /// This is a truncated or tampered download: the sidecar is honest, the payload
    /// is not.
    #[test]
    fn a_corrupted_download_is_refused_and_nothing_is_replaced() {
        let dir = tmpdir("corrupt");
        let target = existing_binary(&dir);

        let honest = b"the real release bytes";
        let digest = sha256(honest);
        let sha = format!("{}  {ASSET}", hex(&digest));

        // Same sidecar, different payload.
        let server = FakeRelease::serve(routes_with(
            b"tampered release bytes",
            &sha,
            "AAAA", // never reached: the digest check runs first
        ));

        let outcome = fetch_verify_install(&server.base, ASSET, &target);
        assert!(
            matches!(outcome, FetchOutcome::VerificationFailed(ref w) if w.contains("DigestMismatch")),
            "expected a digest refusal, got {outcome:?}"
        );
        assert!(
            still_intact(&target),
            "a refused upgrade must leave the working binary in place"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A release signed by somebody else is refused even though its digest is
    /// correct and its signature is well formed.
    #[test]
    fn a_release_signed_by_the_wrong_key_is_refused() {
        use ed25519_dalek::{Signer, SigningKey};

        let dir = tmpdir("wrongkey");
        let target = existing_binary(&dir);

        let bin = b"a release built by somebody else";
        let digest = sha256(bin);
        let sha = format!("{}  {ASSET}", hex(&digest));

        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let sig = base64_encode(&attacker.sign(&digest).to_bytes());

        let server = FakeRelease::serve(routes_with(bin, &sha, &sig));
        let outcome = fetch_verify_install(&server.base, ASSET, &target);

        assert!(
            matches!(outcome, FetchOutcome::VerificationFailed(ref w) if w.contains("BadSignature")),
            "a valid signature under the WRONG key must not install: {outcome:?}"
        );
        assert!(still_intact(&target));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A malformed signature sidecar is refused rather than skipped.
    #[test]
    fn a_malformed_signature_is_refused() {
        let dir = tmpdir("malformed");
        let target = existing_binary(&dir);

        let bin = b"bytes";
        let sha = format!("{}  {ASSET}", hex(&sha256(bin)));
        let server = FakeRelease::serve(routes_with(bin, &sha, "not base64 at all !!!"));

        let outcome = fetch_verify_install(&server.base, ASSET, &target);
        assert!(
            matches!(outcome, FetchOutcome::VerificationFailed(_)),
            "{outcome:?}"
        );
        assert!(still_intact(&target));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A missing sidecar fails the download rather than proceeding unverified.
    ///
    /// The dangerous shape would be treating an absent signature as "unsigned, but
    /// the bytes are fine".
    #[test]
    fn a_missing_signature_sidecar_stops_the_upgrade() {
        let dir = tmpdir("nosig");
        let target = existing_binary(&dir);

        let bin = b"bytes";
        let sha = format!("{}  {ASSET}", hex(&sha256(bin)));
        let mut routes = routes_with(bin, &sha, "");
        routes.remove(&format!("{ASSET}.sig"));

        let server = FakeRelease::serve(routes);
        let outcome = fetch_verify_install(&server.base, ASSET, &target);

        assert!(
            matches!(outcome, FetchOutcome::DownloadFailed(ref w) if w.contains("signature")),
            "an absent signature must stop the upgrade, not be treated as unsigned: {outcome:?}"
        );
        assert!(still_intact(&target));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A release that is not published at all leaves everything alone.
    #[test]
    fn a_missing_release_leaves_the_binary_alone() {
        let dir = tmpdir("missing");
        let target = existing_binary(&dir);

        let server = FakeRelease::serve(HashMap::new());
        let outcome = fetch_verify_install(&server.base, ASSET, &target);

        assert!(
            matches!(outcome, FetchOutcome::DownloadFailed(_)),
            "{outcome:?}"
        );
        assert!(still_intact(&target));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `--check` is not an upgrade, asserted on the decision the command makes.
    ///
    /// The source-grep test this replaces claimed the same thing by looking at
    /// where a substring appeared in the file.
    #[test]
    fn check_only_never_reaches_the_install_path() {
        use {plan_invocation, Invocation};

        assert_eq!(plan_invocation(&["--check".to_string()]), Invocation::Check);
        assert_ne!(
            plan_invocation(&["--check".to_string()]),
            Invocation::Upgrade { forced: false },
            "the defect that shipped on 2026-08-21 was exactly this equality"
        );
    }

    // ── small helpers, kept local so this file adds no dependencies ─────────────

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(bytes).into()
    }

    fn base64_encode(bytes: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }
}
