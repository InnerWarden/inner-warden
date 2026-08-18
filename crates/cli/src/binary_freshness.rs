//! Is the binary this process is running still the one installed on disk?
//!
//! # Why this exists
//!
//! `innerwarden upgrade` writes the new binary beside the old one and renames it
//! over the top. That is the correct way to replace a running program on Unix,
//! and it means the swap is atomic and nothing ever sees a half-written file.
//! It also means a process that is ALREADY RUNNING keeps the old inode until it
//! exits: the file it holds open is unlinked, not modified.
//!
//! For a short-lived command that is invisible. For the dashboard, which people
//! leave running, it produced this on a real machine:
//!
//! ```text
//! innerwarden --version   -> 1.3.3   (reads the file on disk)
//! the dashboard's page    -> 1.3.0   (the bytes it is actually executing)
//! ```
//!
//! Nine days apart, and the upgrade's own closing line tells the operator to
//! "confirm with innerwarden --version" — which reads the surface that agrees
//! and points away from the one that does not.
//!
//! Neither number was wrong. The dashboard really was serving 1.3.0. What was
//! wrong was a page stating a version as though it were the state of the world,
//! when it was only the state of one process.
//!
//! # How it detects the swap
//!
//! At startup the dashboard records the identity — device and inode — of the
//! file at its own path. A later stat of the SAME PATH returns the identity of
//! whatever is there NOW. If they differ, the file was replaced underneath the
//! running process, so what is being served is no longer what is installed.
//!
//! Deliberately not done: executing the new binary to read its version. It is a
//! stronger claim to say "the installed binary changed" than to spawn something
//! in order to decorate the message, and a dashboard should not be running
//! executables to render a page.

/// Identity of a file on disk: the pair that changes when a rename puts a
/// different file at the same path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
}

#[cfg(unix)]
pub fn identity_of(path: &std::path::Path) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt as _;
    let meta = std::fs::metadata(path).ok()?;
    Some(FileIdentity {
        device: meta.dev(),
        inode: meta.ino(),
    })
}

#[cfg(not(unix))]
pub fn identity_of(_path: &std::path::Path) -> Option<FileIdentity> {
    // Windows replaces binaries by a different mechanism and cannot rename over
    // a running executable at all, so the stale-process case this guards
    // against does not arise there. Reporting "unknown" is honest; inventing an
    // identity to compare would not be.
    None
}

/// What the two identities mean together.
///
/// `None` for either side is not evidence of anything: an unreadable path is a
/// question this cannot answer, and it must not be answered as "replaced" —
/// that would put an upgrade notice on a page whenever a stat failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// Running the file that is installed.
    Current,
    /// The file at this path is not the one this process is executing.
    Superseded,
    /// Could not tell. Says nothing either way.
    Unknown,
}

pub fn compare(started_with: Option<FileIdentity>, on_disk_now: Option<FileIdentity>) -> Freshness {
    match (started_with, on_disk_now) {
        (Some(started), Some(now)) if started == now => Freshness::Current,
        (Some(_), Some(_)) => Freshness::Superseded,
        _ => Freshness::Unknown,
    }
}

/// Snapshot taken once, when the long-running process starts.
#[derive(Debug, Clone, Copy)]
pub struct StartupIdentity {
    identity: Option<FileIdentity>,
}

impl StartupIdentity {
    /// Record what this process is executing. Called once at startup: taking it
    /// later would compare the new file against itself and never report a swap.
    pub fn capture() -> Self {
        Self {
            identity: std::env::current_exe()
                .ok()
                .and_then(|path| identity_of(&path)),
        }
    }

    #[cfg(test)]
    pub fn from_identity(identity: Option<FileIdentity>) -> Self {
        Self { identity }
    }

    /// Re-stat this process's own path and say whether it still holds the file
    /// that was there at startup.
    pub fn freshness(&self) -> Freshness {
        let on_disk = std::env::current_exe()
            .ok()
            .and_then(|path| identity_of(&path));
        compare(self.identity, on_disk)
    }

    /// The freshness against an explicit current identity, so the comparison
    /// can be exercised without renaming files under a running test.
    #[cfg(test)]
    pub fn freshness_against(&self, on_disk_now: Option<FileIdentity>) -> Freshness {
        compare(self.identity, on_disk_now)
    }
}

/// The sentence a reader gets when the process is behind the installed file.
///
/// It names both facts, because the operator needs to know the page is honest
/// AND that there is something to do about it. "Restart" rather than a specific
/// command: how the dashboard is supervised is the operator's business, and
/// guessing wrong there is worse than saying less.
pub const SUPERSEDED_NOTE: &str =
    "A newer InnerWarden binary is installed on disk. This dashboard is still \
     running the version it started with; restart it to serve the installed one.";

#[cfg(test)]
mod tests {
    use super::*;

    fn id(device: u64, inode: u64) -> Option<FileIdentity> {
        Some(FileIdentity { device, inode })
    }

    /// The production case: the file at the path was replaced by a rename, so
    /// the inode moved while the process kept the old one.
    #[test]
    fn a_replaced_binary_is_superseded() {
        assert_eq!(compare(id(1, 100), id(1, 200)), Freshness::Superseded);
    }

    /// The same file is the same file. An upgrade that has not happened must
    /// not put a notice on the page.
    #[test]
    fn an_untouched_binary_is_current() {
        assert_eq!(compare(id(1, 100), id(1, 100)), Freshness::Current);
    }

    /// A path can be replaced across filesystems, where the inode alone could
    /// collide. The device is part of the identity for that reason.
    #[test]
    fn the_same_inode_on_a_different_device_is_not_the_same_file() {
        assert_eq!(compare(id(1, 100), id(2, 100)), Freshness::Superseded);
    }

    /// A stat that fails answers nothing. Reporting "superseded" on an
    /// unreadable path would show an upgrade notice for a permissions error,
    /// which is a lie with a call to action attached.
    #[test]
    fn an_unreadable_path_says_nothing_rather_than_accusing() {
        assert_eq!(compare(id(1, 100), None), Freshness::Unknown);
        assert_eq!(compare(None, id(1, 100)), Freshness::Unknown);
        assert_eq!(compare(None, None), Freshness::Unknown);
    }

    #[test]
    fn the_startup_snapshot_compares_against_what_it_captured() {
        let snapshot = StartupIdentity::from_identity(id(7, 42));
        assert_eq!(snapshot.freshness_against(id(7, 42)), Freshness::Current);
        assert_eq!(snapshot.freshness_against(id(7, 43)), Freshness::Superseded);
        assert_eq!(snapshot.freshness_against(None), Freshness::Unknown);
    }

    /// A real swap, end to end, through the filesystem rather than through
    /// hand-made identities: write a file, stat it, rename another over it, and
    /// confirm the identity moved. This is the mechanism `upgrade` uses.
    #[test]
    fn a_rename_over_the_path_moves_its_identity_on_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("innerwarden");
        std::fs::write(&target, b"old").expect("write old");
        let before = identity_of(&target);
        assert!(before.is_some(), "the file we just wrote must be stattable");

        let staged = dir.path().join("innerwarden.new");
        std::fs::write(&staged, b"new").expect("write new");
        std::fs::rename(&staged, &target).expect("rename over");

        let after = identity_of(&target);
        assert_eq!(
            compare(before, after),
            Freshness::Superseded,
            "a rename-over must read as superseded; this is exactly what upgrade does"
        );
    }
}
