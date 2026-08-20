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

/// Full download URL for an asset, plus its two sidecars.
///
/// The sidecars are not optional: [`super::release_verify::verify_release`]
/// needs both, and a missing one is a failure rather than a skipped check.
pub fn urls_for(asset: &str) -> (String, String, String) {
    (
        format!("{RELEASE_BASE}/{asset}"),
        format!("{RELEASE_BASE}/{asset}.sha256"),
        format!("{RELEASE_BASE}/{asset}.sig"),
    )
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
        let (bin, sha, sig) = urls_for("innerwarden-linux-x86_64");
        assert!(bin.ends_with("/innerwarden-linux-x86_64"));
        assert_eq!(sha, format!("{bin}.sha256"));
        assert_eq!(sig, format!("{bin}.sig"));
        assert!(bin.starts_with("https://"), "never plain http");
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
