//! Thin I/O for the per-agent profiles: read the two files the way a policy
//! file is read, and keep the snapshot the audit line is computed from. The
//! decisions are in `agent_profiles` and `innerwarden_agent_guard::profiles`.
//!
//! A host with neither file pays one failed open of each and nothing else: no
//! snapshot is read or written, no line is emitted.

use std::path::{Path, PathBuf};

use innerwarden_agent_guard::profiles::{
    MAX_PROFILES_BYTES, SYSTEM_PROFILES_PATH, USER_PROFILES_PATH,
};

use crate::agent_profiles::{audit_step, state_from, FileRead, ProfilesState};

/// The snapshot of the last profiles seen, beside the record.
const SNAPSHOT_NAME: &str = "agent-profiles.seen.json";

/// The largest snapshot read back.
const MAX_SNAPSHOT_BYTES: u64 = 256 * 1024;

/// Who must own a file of profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Owner {
    /// The system file: root.
    Root,
    /// The user's file: this process's user (or root).
    Me,
    /// The user's file of another account, read by root for it: that
    /// account (or root).
    #[cfg_attr(not(unix), allow(dead_code))]
    Account(u32),
}

/// The user's file, under the home this process runs with.
pub(crate) fn user_path() -> Option<PathBuf> {
    innerwarden_agent_guard::hook::home_dir()
        .ok()
        .filter(|home| home.is_absolute())
        .map(|home| home.join(USER_PROFILES_PATH))
}

/// The profiles in force on this host, from both files, with the change (if
/// any) reported to the guard event stream.
pub fn load() -> ProfilesState {
    let state = state();
    audit(&state);
    state
}

/// The profiles in force on this host, from both files, reporting nothing:
/// for a reader that shows them (the dashboard) rather than applies them.
pub fn state() -> ProfilesState {
    let (system, (user_label, user)) = read_both();
    state_from((SYSTEM_PROFILES_PATH, system), (&user_label, user))
}

/// The two files as found: the system file, and the user's with the path it
/// is named by.
fn read_both() -> (FileRead, (String, FileRead)) {
    let user = user_path();
    let user_label = user
        .as_ref()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|| format!("~/{USER_PROFILES_PATH}"));
    let system = read(Path::new(SYSTEM_PROFILES_PATH), Owner::Root);
    let user = user
        .as_deref()
        .map(|path| read(path, Owner::Me))
        .unwrap_or(FileRead::Absent);
    (system, (user_label, user))
}

/// One open of `path`: no link followed, no wait on a FIFO, a regular file
/// of the right owner that its group and others cannot write, no more than
/// the cap read. A path that does not exist, or that this user cannot even
/// look up (a directory closed to it), is absent: a file this user cannot
/// see is not one that governs it. A file it can see and not read is refused.
pub(crate) fn read(path: &Path, owner: Owner) -> FileRead {
    use std::io::Read;

    let file = match innerwarden_safe_io::open_no_follow(path) {
        Ok(file) => file,
        Err(error) => return open_failure(path, &error),
    };
    let Ok(metadata) = file.metadata() else {
        return FileRead::Refused("cannot be inspected".into());
    };
    if !innerwarden_safe_io::is_regular_file(&metadata) {
        return FileRead::Refused("is not a regular file".into());
    }
    if let Some(why) = owner_refusal(&metadata, owner) {
        return FileRead::Refused(why);
    }
    if metadata.len() > MAX_PROFILES_BYTES as u64 {
        return FileRead::Refused(format!(
            "is larger than the {MAX_PROFILES_BYTES} bytes a file of profiles may hold"
        ));
    }
    let mut bytes = Vec::new();
    if file
        .take(MAX_PROFILES_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return FileRead::Refused("could not be read".into());
    }
    if bytes.len() > MAX_PROFILES_BYTES {
        return FileRead::Refused("grew while it was read".into());
    }
    FileRead::Bytes(bytes)
}

fn open_failure(path: &Path, error: &std::io::Error) -> FileRead {
    use std::io::ErrorKind;
    #[cfg(unix)]
    if error.raw_os_error() == Some(libc::ELOOP) {
        return FileRead::Refused(
            "is a symbolic link; a file of profiles is read only as itself".into(),
        );
    }
    #[cfg(unix)]
    if error.raw_os_error() == Some(libc::ENOTDIR) {
        return FileRead::Absent;
    }
    match error.kind() {
        ErrorKind::NotFound => FileRead::Absent,
        ErrorKind::PermissionDenied => match std::fs::symlink_metadata(path) {
            // It is there and this user may not read it.
            Ok(_) => FileRead::Refused(
                "cannot be read by this user; it must be readable by every user whose agents \
                 it governs"
                    .into(),
            ),
            // The directory is closed to this user: nothing there is for it.
            Err(_) => FileRead::Absent,
        },
        other => FileRead::Refused(format!("cannot be opened ({other})")),
    }
}

#[cfg(unix)]
fn owner_refusal(metadata: &std::fs::Metadata, owner: Owner) -> Option<String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // SAFETY: geteuid takes no arguments and cannot fail.
    let euid = unsafe { libc::geteuid() };
    let uid = metadata.uid();
    let owned = match owner {
        Owner::Root => crate::agent_profiles::system_owner_is_root(uid, root_view),
        Owner::Me => uid == euid || uid == 0,
        Owner::Account(account) => uid == account || uid == 0,
    };
    if !owned {
        return Some(match owner {
            Owner::Root => format!("is owned by uid {uid}, not root"),
            Owner::Me => format!("is owned by uid {uid}, not by this user ({euid})"),
            Owner::Account(account) => format!("is owned by uid {uid}, not by uid {account}"),
        });
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Some("can be written by its group or by others".into());
    }
    None
}

#[cfg(not(unix))]
fn owner_refusal(_metadata: &std::fs::Metadata, _owner: Owner) -> Option<String> {
    None
}

/// Who root is where this process runs, read only for a system file uid 0
/// does not own: the user namespace's map, the kernel's overflow uid, and
/// whether the jail's launcher proved the way to the system file root's (its
/// launch record, or the marker a plain jail's launcher mounts, at its
/// place). Elsewhere than Linux: nothing, so only uid 0 is root.
#[cfg(unix)]
fn root_view() -> crate::agent_profiles::RootView {
    #[cfg(target_os = "linux")]
    {
        let mounted = |path: &str| {
            std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_file())
        };
        crate::agent_profiles::RootView {
            maps_root: std::fs::read_to_string("/proc/self/uid_map")
                .ok()
                .map(|map| crate::agent_profiles::uid_map_maps_root(&map)),
            overflow_uid: std::fs::read_to_string("/proc/sys/kernel/overflowuid")
                .ok()
                .and_then(|text| text.trim().parse::<u32>().ok()),
            launcher_proved: crate::agent_profiles::launcher_proved(
                mounted(innerwarden_agent_guard::identity::JAIL_RECORD_PATH),
                mounted(crate::agent_profiles::SYSTEM_PROFILES_MARKER_PATH),
            ),
        }
    }
    #[cfg(not(target_os = "linux"))]
    crate::agent_profiles::RootView::default()
}

/// Report what changed since the last process loaded the profiles, once:
/// the snapshot is replaced only if no other process replaced it first, and
/// only the process whose replace took writes the lines. Best-effort, like
/// every write beside the record; with no file on the host, nothing.
fn audit(state: &ProfilesState) {
    if matches!(state, ProfilesState::Off) {
        return;
    }
    let Some(dir) = crate::graph_io::sink_dir() else {
        return;
    };
    let path = dir.join(SNAPSHOT_NAME);
    let previous = read_snapshot(&path);
    let Some((bytes, changes)) = audit_step(previous.as_deref(), state) else {
        return;
    };
    if innerwarden_agent_guard::file_update::replace_if_unchanged_no_symlinks(
        &dir,
        &path,
        previous.as_deref(),
        &bytes,
    )
    .is_err()
    {
        return;
    }
    for change in &changes {
        crate::graph_io::record_rule_change(change.layer, change);
    }
}

/// The snapshot's bytes: one open, no link, a regular file, bounded. Anything
/// else is no snapshot.
fn read_snapshot(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let file = innerwarden_safe_io::open_no_follow(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !innerwarden_safe_io::is_regular_file(&metadata) || metadata.len() > MAX_SNAPSHOT_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_SNAPSHOT_BYTES).read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn write(dir: &Path, name: &str, body: &str, mode: u32) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn a_missing_file_or_folder_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            read(&dir.path().join("nope.toml"), Owner::Me),
            FileRead::Absent
        );
        assert_eq!(
            read(&dir.path().join("nope/agent-profiles.toml"), Owner::Me),
            FileRead::Absent
        );
        let file = write(dir.path(), "plain", "x", 0o644);
        assert_eq!(
            read(&file.join("under-a-file"), Owner::Me),
            FileRead::Absent
        );
    }

    #[test]
    fn the_users_own_file_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "p.toml", "schema_version = 1\n", 0o644);
        assert_eq!(
            read(&path, Owner::Me),
            FileRead::Bytes(b"schema_version = 1\n".to_vec())
        );
    }

    /// A file another account could have written is not this policy.
    ///
    /// FAILS ON REVERT: drop the mode check in `owner_refusal` and the
    /// group-writable file is read.
    #[test]
    fn a_file_others_can_write_a_link_or_a_folder_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o664, 0o646, 0o666] {
            let path = write(dir.path(), &format!("p{mode:o}.toml"), "x", mode);
            assert!(
                matches!(read(&path, Owner::Me), FileRead::Refused(ref why) if why.contains("written by its group or by others")),
                "{mode:o}"
            );
        }
        let real = write(dir.path(), "real.toml", "x", 0o644);
        let link = dir.path().join("link.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(
            matches!(read(&link, Owner::Me), FileRead::Refused(ref why) if why.contains("symbolic link"))
        );
        let folder = dir.path().join("folder.toml");
        std::fs::create_dir(&folder).unwrap();
        assert!(matches!(read(&folder, Owner::Me), FileRead::Refused(_)));
        let big = write(
            dir.path(),
            "big.toml",
            &"#".repeat(MAX_PROFILES_BYTES + 1),
            0o644,
        );
        assert!(
            matches!(read(&big, Owner::Me), FileRead::Refused(ref why) if why.contains("larger"))
        );
    }

    /// The system file must be root's: one the user owns is refused (unless
    /// the test runs as root, where it is root's).
    #[test]
    fn a_system_file_not_owned_by_root_is_refused() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "p.toml", "schema_version = 1\n", 0o644);
        assert!(
            matches!(read(&path, Owner::Root), FileRead::Refused(ref why) if why.contains("not root"))
        );
    }

    #[test]
    fn a_fifo_does_not_hang_the_read() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("p.toml");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(matches!(read(&fifo, Owner::Me), FileRead::Refused(_)));
    }

    #[test]
    fn a_snapshot_is_read_only_as_a_plain_bounded_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), SNAPSHOT_NAME, "{}", 0o600);
        assert_eq!(read_snapshot(&path), Some(b"{}".to_vec()));
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(read_snapshot(&link), None);
        assert_eq!(read_snapshot(&dir.path().join("none.json")), None);
    }
}
