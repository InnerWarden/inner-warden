//! Which release asset this build should download, and where to put it.
//!
//! Split out from `upgrade` so the platform mapping and the replace strategy are
//! testable on any host, without network or a real binary swap. The I/O shell in
//! `upgrade` stays thin on purpose: everything that can be decided from pure
//! inputs is decided here.

use std::path::{Path, PathBuf};

/// Base URL of the rolling release the free channel publishes to.
pub const RELEASE_BASE: &str =
    "https://github.com/InnerWarden/innerwarden-releases/releases/download/iw-guard";

/// The release asset name for an (os, arch) pair, matching what the release
/// workflow publishes.
///
/// `None` for a platform the free channel does not publish, so the updater can
/// say so instead of 404ing on a guessed name.
pub fn asset_name(os: &str, arch: &str) -> Option<String> {
    let arch = match arch {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        _ => return None,
    };
    Some(match os {
        "linux" => format!("innerwarden-linux-{arch}"),
        "macos" => format!("innerwarden-macos-{arch}"),
        "windows" => format!("innerwarden-windows-{arch}.exe"),
        _ => return None,
    })
}

/// The asset for the host this binary is running on.
pub fn asset_for_this_host() -> Option<String> {
    asset_name(std::env::consts::OS, std::env::consts::ARCH)
}

/// The download URL for an asset under a base, plus its two sidecars.
///
/// The sidecars are not optional: [`super::release_verify::verify_release`]
/// needs both, and a missing one is a failure rather than a skipped check.
///
/// The base is a parameter so a test can point the whole download-and-verify
/// path at a local server. Before that, every test of that path either hit the
/// real internet or asserted the order of substrings in the source, and the
/// latter is what shipped `upgrade --check` performing a real upgrade.
///
/// Production has exactly one caller and it passes [`RELEASE_BASE`].
pub fn urls_from(base: &str, asset: &str) -> (String, String, String) {
    (
        format!("{base}/{asset}"),
        format!("{base}/{asset}.sha256"),
        format!("{base}/{asset}.sig"),
    )
}

/// The asset that names the version the rolling release currently carries.
///
/// It is the Scoop manifest, which the release workflow regenerates from the
/// built binary's own `--version` and uploads alongside the binaries. That makes
/// it the honest answer to "what would I get?": it is derived from the artifact
/// rather than from the tag it was cut from, and the workflow refuses to publish
/// when the two disagree.
pub const VERSION_MANIFEST_ASSET: &str = "innerwarden.json";

/// URL of the version manifest under an arbitrary base. Split for the same
/// reason as [`urls_from`]: so a test can serve one.
pub fn manifest_url_from(base: &str) -> String {
    format!("{base}/{VERSION_MANIFEST_ASSET}")
}

/// The version the published release carries, or `None` if the manifest did not
/// say.
///
/// Fails closed into `None` on anything unexpected. A caller must not turn "did
/// not say" into "an upgrade is available": that is the failure this whole
/// change exists to remove.
pub fn published_version(manifest_json: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(manifest_json).ok()?;
    let raw = v.get("version")?.as_str()?.trim();
    if raw.is_empty() {
        return None;
    }
    Some(raw.to_string())
}

/// What `innerwarden upgrade --check` established.
///
/// A value rather than a printed sentence, so the decision is testable without
/// a network and without capturing stdout. The previous implementation had no
/// decision to test: it fetched the `.sha256` sidecar, discarded it, and printed
/// "Run `innerwarden upgrade` to install it" on any HTTP success, which it said
/// on 1.3.7 while 1.3.7 was the published release.
///
/// The third variant is the point. `--check` must never report an upgrade
/// because it could not tell, which is the rule [`crate::status`] exists to
/// enforce: never report "off" when you mean "could not tell".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckOutcome {
    /// The published build is the one already installed.
    UpToDate { version: String },
    /// A different build is published, and `upgrade` would install it.
    Available {
        published: String,
        installed: String,
    },
    /// The release answered and did not name a version. Never rendered as an
    /// available upgrade.
    Undetermined,
}

/// Decide what to report from the installed version and the published manifest.
pub fn check_outcome(installed: &str, manifest_json: &str) -> CheckOutcome {
    match published_version(manifest_json) {
        None => CheckOutcome::Undetermined,
        Some(published) if published == installed => CheckOutcome::UpToDate { version: published },
        Some(published) => CheckOutcome::Available {
            published,
            installed: installed.to_string(),
        },
    }
}

/// The lines `--check` prints, given what it established.
///
/// `managed` is taken into account because telling an npm user to run
/// `innerwarden upgrade` is the same lie in a different place: that command now
/// refuses, so pointing them at it would waste the round trip.
pub fn check_lines(outcome: &CheckOutcome, asset: &str, managed: Managed) -> Vec<String> {
    let install_command = match managed {
        Managed::Npm => "npm install -g innerwarden@latest",
        Managed::Direct => "innerwarden upgrade",
    };
    match outcome {
        CheckOutcome::UpToDate { version } => vec![
            format!("InnerWarden Community {version}"),
            format!("  Already on the latest build: the published release carries {version} too."),
            "  Nothing to do.".into(),
        ],
        CheckOutcome::Available {
            published,
            installed,
        } => vec![
            format!("InnerWarden Community {installed}"),
            format!("  The published release carries {published} ({asset})."),
            format!("  Run `{install_command}` to install {published}."),
        ],
        CheckOutcome::Undetermined => vec![
            "InnerWarden Community: could not determine the published version.".into(),
            "  The release answered but did not name a version, so there is nothing".into(),
            "  to compare against. Not reporting an upgrade on a guess.".into(),
            "  Nothing was downloaded. The installed binary is untouched.".into(),
        ],
    }
}

/// Where to stage the download: beside the binary being replaced, never in a
/// world-writable temp directory.
///
/// Staging in `/tmp` would open the window an attacker needs: the verified bytes
/// sit there between verification and the rename, and on a shared machine anyone
/// can swap them in that window. Staging in the destination directory also keeps
/// the final step a same-filesystem rename, which is atomic; a cross-device move
/// is a copy, and a copy can be interrupted half-written.
pub fn staging_path(target: &Path) -> PathBuf {
    let file = target
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "innerwarden".to_string());
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    dir.join(format!(".{file}.upgrade"))
}

/// Who owns the installed binary, which decides what "upgrade" even means.
///
/// `upgrade` replaces the file it is running from. That is right for the
/// installer's own copy and wrong for a copy another package manager put
/// there: overwriting npm's file leaves npm believing it still ships the old
/// version, and the next `npm install -g` silently reverts the upgrade.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Managed {
    /// Installed by `npm install -g innerwarden`.
    Npm,
    /// Installed by the shell installer, or built locally.
    Direct,
}

/// Classify an install from the path the binary runs from.
///
/// npm's global layout puts the real binary under `node_modules`, which is the
/// one marker that is stable across npm versions, prefixes, and platforms.
pub fn managed_by(target: &Path) -> Managed {
    if target.components().any(|c| c.as_os_str() == "node_modules") {
        Managed::Npm
    } else {
        Managed::Direct
    }
}

/// Must this invocation stop before anything is downloaded?
///
/// Pure, and consulted by `upgrade` BEFORE the first byte is fetched. Until now
/// `managed_by` had two callers and both were on the failure path, so the npm
/// hazard was only ever announced to people whose upgrade had already failed for
/// an unrelated reason. The case it was written for, a user-owned npm prefix,
/// upgrades successfully and is reverted by the next `npm install -g`.
///
/// `check_only` never refuses: reporting a version changes nothing, and the
/// report names npm's own command instead. `forced` is the user saying they know.
pub fn npm_refusal_applies(target: &Path, check_only: bool, forced: bool) -> bool {
    !check_only && !forced && managed_by(target) == Managed::Npm
}

/// What to tell someone whose binary could not be replaced.
///
/// A beginner reading "Permission denied" has no way to know whether the fix is
/// `sudo`, their package manager, or a reinstall. Worse, on an npm install the
/// obvious guess is the wrong one: `sudo innerwarden upgrade` would succeed and
/// then be undone by the next `npm install -g`. Name the actual next command.
///
/// `is_root` is passed in rather than read here so the decision stays pure and
/// the root case is testable on any host.
pub fn cannot_replace_advice(target: &Path, is_root: bool) -> Vec<String> {
    let mut out = Vec::new();
    match managed_by(target) {
        Managed::Npm => {
            out.push(format!(
                "This copy is managed by npm ({}).",
                target.display()
            ));
            out.push("Upgrade it the way it was installed:".into());
            out.push("    npm install -g innerwarden@latest".into());
            out.push(String::new());
            out.push(
                "Do not use sudo for this. Replacing npm's file by hand leaves npm \
                 believing it still ships the old version, and the next \
                 `npm install -g` puts the old one back."
                    .into(),
            );
        }
        Managed::Direct if !is_root => {
            out.push(format!(
                "{} is not writable by this user.",
                target.display()
            ));
            out.push("Re-run with elevated privileges:".into());
            out.push("    sudo innerwarden upgrade".into());
        }
        Managed::Direct => {
            out.push(format!(
                "{} could not be replaced even as root.",
                target.display()
            ));
            out.push(
                "The filesystem is most likely read-only, or the file is immutable \
                 (`lsattr`). Reinstall instead:"
                    .into(),
            );
            out.push("    curl -fsSL https://innerwarden.com/free | sh".into());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// npm's global install is the case where the obvious fix is the wrong one.
    #[test]
    fn an_npm_install_is_recognised_from_its_path() {
        let p = Path::new(
            "/usr/local/lib/node_modules/innerwarden/node_modules/@innerwarden/cli-linux-x64/bin/innerwarden",
        );
        assert_eq!(managed_by(p), Managed::Npm);
        let advice = cannot_replace_advice(p, false).join("\n");
        assert!(
            advice.contains("npm install -g innerwarden@latest"),
            "an npm install must be pointed at npm, got:\n{advice}"
        );
        assert!(
            advice.contains("Do not use sudo"),
            "sudo works here and is exactly what makes the upgrade revert later:\n{advice}"
        );
    }

    /// Being root does not make overwriting npm's file the right move.
    #[test]
    fn root_does_not_change_the_advice_for_an_npm_install() {
        let p = Path::new("/usr/lib/node_modules/innerwarden/bin/innerwarden");
        let advice = cannot_replace_advice(p, true).join("\n");
        assert!(
            advice.contains("npm install -g innerwarden@latest"),
            "{advice}"
        );
        assert!(
            !advice.contains("sudo innerwarden upgrade"),
            "escalating would overwrite npm's file, which is the bug:\n{advice}"
        );
    }

    /// The ordinary case: installer copy, unprivileged user.
    #[test]
    fn a_direct_install_that_is_not_writable_asks_for_sudo() {
        let p = Path::new("/usr/local/bin/innerwarden");
        let advice = cannot_replace_advice(p, false).join("\n");
        assert!(advice.contains("sudo innerwarden upgrade"), "{advice}");
        assert!(!advice.contains("npm install"), "{advice}");
    }

    /// Already root and still refused: sudo is not the answer, so do not say it.
    #[test]
    fn a_direct_install_failing_as_root_does_not_suggest_sudo() {
        let p = Path::new("/usr/local/bin/innerwarden");
        let advice = cannot_replace_advice(p, true).join("\n");
        assert!(
            !advice.contains("sudo innerwarden upgrade"),
            "telling root to use sudo sends them round the same loop:\n{advice}"
        );
        assert!(advice.contains("read-only"), "{advice}");
    }

    /// REGRESSION ANCHOR. The npm hazard was detected and documented, and the
    /// only two callers of `managed_by` were on the FAILURE path.
    ///
    /// So the warning appeared only when the replace had also failed, which
    /// needs a root-owned npm prefix. The install page recommends
    /// `npm config set prefix ~/.npm-global`, which is user-owned, so the
    /// replace succeeds: "Upgrade complete", and the next `npm install -g`
    /// silently puts the old binary back. The one case the advice existed for
    /// was the one case that never saw it.
    ///
    /// FAILS ON REVERT: return `false` unconditionally, i.e. stop consulting
    /// `managed_by` before the download, and the npm case stops refusing.
    #[test]
    fn an_npm_install_is_refused_before_anything_is_downloaded() {
        let npm = Path::new("/home/lab/.npm-global/lib/node_modules/innerwarden/bin/innerwarden");
        assert_eq!(managed_by(npm), Managed::Npm, "precondition");
        assert!(
            npm_refusal_applies(npm, false, false),
            "a plain `innerwarden upgrade` on an npm copy must refuse"
        );
    }

    /// The three ways the refusal must NOT fire, so it cannot become a blanket
    /// "upgrade is broken".
    #[test]
    fn the_npm_refusal_spares_check_forced_and_direct_installs() {
        let npm = Path::new("/usr/local/lib/node_modules/innerwarden/bin/innerwarden");
        let direct = Path::new("/usr/local/bin/innerwarden");

        assert!(
            !npm_refusal_applies(npm, true, false),
            "--check changes nothing, so it reports rather than refusing"
        );
        assert!(
            !npm_refusal_applies(npm, false, true),
            "--yes is the user saying they know what it costs"
        );
        assert!(
            !npm_refusal_applies(direct, false, false),
            "an installer copy is exactly what upgrade is for"
        );
        assert!(
            !npm_refusal_applies(direct, true, false),
            "{}",
            direct.display()
        );
    }

    #[test]
    fn a_plain_path_is_not_mistaken_for_npm() {
        assert_eq!(
            managed_by(Path::new("/usr/local/bin/innerwarden")),
            Managed::Direct
        );
        assert_eq!(
            managed_by(Path::new("/home/lab/.local/bin/innerwarden")),
            Managed::Direct
        );
    }

    #[test]
    fn every_published_platform_maps_to_its_asset() {
        assert_eq!(
            asset_name("linux", "x86_64").as_deref(),
            Some("innerwarden-linux-x86_64")
        );
        assert_eq!(
            asset_name("macos", "aarch64").as_deref(),
            Some("innerwarden-macos-aarch64")
        );
        assert_eq!(
            asset_name("windows", "x86_64").as_deref(),
            Some("innerwarden-windows-x86_64.exe"),
            "the Windows asset carries the .exe suffix"
        );
    }

    /// An unpublished platform must be named as such, not guessed into a 404.
    #[test]
    fn an_unpublished_platform_has_no_asset() {
        assert_eq!(asset_name("freebsd", "x86_64"), None);
        assert_eq!(asset_name("linux", "riscv64"), None);
    }

    /// The host running the tests is one this project publishes for, so the
    /// mapping cannot silently lose a supported platform.
    #[test]
    fn this_host_resolves_to_a_published_asset() {
        assert!(
            asset_for_this_host().is_some(),
            "no asset for {}/{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        );
    }

    #[test]
    fn both_sidecars_are_derived_from_the_asset() {
        let (bin, sha, sig) = urls_from(RELEASE_BASE, "innerwarden-linux-x86_64");
        assert!(bin.ends_with("/innerwarden-linux-x86_64"));
        assert_eq!(sha, format!("{bin}.sha256"));
        assert_eq!(sig, format!("{bin}.sig"));
        assert!(bin.starts_with("https://"), "never plain http");
    }

    /// The manifest shape the release actually publishes, trimmed to the field
    /// this reads. Kept verbatim so a change to the published layout shows up
    /// here rather than as a silent `Undetermined` on every host.
    const REAL_MANIFEST: &str = r#"{
      "version": "1.3.7",
      "description": "InnerWarden Community Edition",
      "homepage": "https://innerwarden.com",
      "architecture": { "64bit": { "hash": "f5cb" } }
    }"#;

    /// REGRESSION ANCHOR. `upgrade --check` could not answer the one question it
    /// is asked.
    ///
    /// It fetched the `.sha256` sidecar, threw it away, and printed "Run
    /// `innerwarden upgrade` to install it" whenever the HTTP call succeeded. On
    /// 1.3.7, with 1.3.7 published, it still said an upgrade was waiting. A check
    /// that answers "yes" unconditionally is not a check, and users who notice
    /// stop running it.
    ///
    /// FAILS ON REVERT: return `Available` regardless of the versions, which is
    /// what the old code effectively printed.
    #[test]
    fn a_check_on_the_published_version_reports_no_upgrade() {
        let outcome = check_outcome("1.3.7", REAL_MANIFEST);
        assert_eq!(
            outcome,
            CheckOutcome::UpToDate {
                version: "1.3.7".into()
            },
            "1.3.7 installed against 1.3.7 published is not an upgrade"
        );

        let lines = check_lines(&outcome, "innerwarden-linux-x86_64", Managed::Direct).join("\n");
        assert!(
            lines.contains("Already on the latest build"),
            "the report must say so in words: {lines}"
        );
        assert!(
            !lines.contains("Run `innerwarden upgrade`"),
            "there is nothing to install, so do not send anyone to install it: {lines}"
        );
    }

    /// The other half: when a newer build IS published, name the version that
    /// would be installed rather than saying "a build exists".
    #[test]
    fn a_check_behind_the_release_names_the_version_it_would_install() {
        let outcome = check_outcome("1.3.4", REAL_MANIFEST);
        assert_eq!(
            outcome,
            CheckOutcome::Available {
                published: "1.3.7".into(),
                installed: "1.3.4".into()
            }
        );

        let lines = check_lines(&outcome, "innerwarden-linux-x86_64", Managed::Direct).join("\n");
        assert!(lines.contains("1.3.7"), "name what would arrive: {lines}");
        assert!(
            lines.contains("1.3.4"),
            "name what is installed, or there is nothing to compare: {lines}"
        );
        assert!(lines.contains("Run `innerwarden upgrade`"), "{lines}");
    }

    /// A manifest that does not name a version must not become "an upgrade is
    /// available". Never report a verdict when you mean "could not tell".
    #[test]
    fn a_manifest_that_names_no_version_is_undetermined_not_available() {
        for manifest in [
            "{}",
            r#"{"version": ""}"#,
            r#"{"version": 137}"#,
            "not json at all",
            "",
        ] {
            assert_eq!(
                check_outcome("1.3.7", manifest),
                CheckOutcome::Undetermined,
                "{manifest:?} says nothing about a version"
            );
        }

        let lines = check_lines(
            &CheckOutcome::Undetermined,
            "innerwarden-linux-x86_64",
            Managed::Direct,
        )
        .join("\n");
        assert!(
            !lines.to_lowercase().contains("run `innerwarden upgrade`"),
            "an unknown state must not be rendered as an available upgrade: {lines}"
        );
        assert!(lines.contains("could not determine"), "{lines}");
    }

    /// An npm-managed install must not be told to run a command that now
    /// refuses. The check and the upgrade have to agree about what to do next.
    #[test]
    fn a_check_on_an_npm_install_points_at_npm() {
        let outcome = check_outcome("1.3.4", REAL_MANIFEST);
        let lines = check_lines(&outcome, "innerwarden-linux-x86_64", Managed::Npm).join("\n");
        assert!(
            lines.contains("npm install -g innerwarden@latest"),
            "{lines}"
        );
        assert!(
            !lines.contains("Run `innerwarden upgrade`"),
            "that command refuses on an npm copy, so do not recommend it: {lines}"
        );
    }

    #[test]
    fn the_version_manifest_sits_beside_the_binaries() {
        let url = manifest_url_from(RELEASE_BASE);
        assert_eq!(url, format!("{RELEASE_BASE}/innerwarden.json"));
        assert!(url.starts_with("https://"), "never plain http");
    }

    /// REGRESSION ANCHOR. Staging must be beside the target, not in a shared
    /// temp directory: the verified bytes are swappable between verification and
    /// rename, and only a same-filesystem rename is atomic.
    ///
    /// FAILS ON REVERT: stage in `std::env::temp_dir()` and the parent check
    /// trips.
    #[test]
    fn staging_is_beside_the_target_and_hidden() {
        let target = Path::new("/usr/local/bin/innerwarden");
        let staged = staging_path(target);
        assert_eq!(
            staged.parent(),
            target.parent(),
            "same directory, so the rename is atomic"
        );
        assert_ne!(
            staged, target,
            "never write the target before it is verified"
        );
        assert!(
            staged
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with('.'),
            "hidden, so a half-finished upgrade is not mistaken for a binary"
        );
        assert!(
            !staged.starts_with(std::env::temp_dir()),
            "never a shared temp dir"
        );
    }

    /// A bare filename has an empty parent, which must still resolve to the
    /// current directory rather than to the filesystem root.
    #[test]
    fn staging_handles_a_bare_filename() {
        let staged = staging_path(Path::new("innerwarden"));
        assert_eq!(staged.file_name().unwrap(), ".innerwarden.upgrade");
        assert!(
            staged == Path::new(".innerwarden.upgrade")
                || staged == Path::new("./.innerwarden.upgrade"),
            "unexpected staging path: {}",
            staged.display()
        );
        assert!(staged.is_relative(), "must not escape to an absolute path");
    }
}
