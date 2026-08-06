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

#[cfg(test)]
mod tests {
    use super::*;

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
