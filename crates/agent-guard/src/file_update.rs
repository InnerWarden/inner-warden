//! Small fail-closed file replacement primitive for agent configuration edits.
//!
//! Agent configuration files may be read while their owner is running. Writers
//! must therefore never expose a truncated JSON/TOML document. InnerWarden
//! serializes its own edits with a sibling advisory lock, writes and syncs a
//! private sibling, preserves permissions, and only then replaces the target.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fs4::FileExt;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Maximum size accepted when reading an agent CONFIGURATION file.
///
/// This bounds what a hostile or broken agent config can make us read. It is not
/// a sensible bound for every file this module replaces: the narrative graph is
/// an append-heavy store we write ourselves, and applying the config limit to it
/// meant that once it crossed 16 MiB the guard stopped recording entirely and
/// said so only on stderr, which nobody reads. Six hours of a developer's
/// commands went unrecorded before it was noticed.
pub const MAX_CONFIG_BYTES: u64 = 16 * 1024 * 1024;

/// Maximum size accepted for our own append-heavy stores, like the graph.
///
/// Generous next to what the node cap allows (20k nodes measured at ~16 MB), so
/// a store slightly over the config limit still loads and can be pruned back
/// down instead of wedging. The bound still exists: an unbounded read is how a
/// corrupt file takes the process with it.
pub const MAX_OWNED_STORE_BYTES: u64 = 128 * 1024 * 1024;

/// What a file this product CREATES has to look like, taken from the directory
/// it lands in instead of from a constant.
///
/// WHY, from spec-052 and its measurements on test001 (2026-08-28): the paid
/// agent runs as its own `innerwarden` user with `ProtectHome=yes`, which leaves
/// `/home` empty inside its mount namespace, so the record both halves share has
/// to move to `/var/lib/innerwarden/guard/`. That directory is shared: the
/// operator writes it through the free CLI and the `innerwarden` agent user
/// reads it.
///
/// # Mode
///
/// A hardcoded `0600` produces, in that shared directory, a file the agent still
/// cannot read, which is the same "dashboard home page shows an error" symptom
/// by a second route. A hardcoded `0660` everywhere would be the opposite
/// mistake: this module also writes agent configuration inside a private home,
/// and widening those is not something the operator asked for.
///
/// So the directory decides, and neither half fights the other about it. Group
/// write on the directory means the group is already trusted to write there, and
/// a group readable/writable file is consistent with that; anything else stays
/// owner-only.
///
/// # Group, which is the half a mode alone cannot cover
///
/// Measured on test001 (Ubuntu 24.04) on 2026-08-28:
///
/// ```text
/// dir 0770 test001:adm  -> a new file lands test001:test001
/// dir 2770 test001:adm  -> a new file lands test001:adm
/// ```
///
/// Linux gives a new file the CREATOR's primary group unless the directory
/// carries the setgid bit. So mode `0660` inside a plain
/// `0770 innerwarden:innerwarden` directory produces `<operator>:<operator>`,
/// and the `innerwarden` user that has to read it falls into OTHER with no bits
/// at all: `graph_absent` again, reached by a third route, and no assertion
/// about mode bits can see it.
///
/// Two things therefore have to be true, and this crate owns the second so the
/// free half is correct whichever way the installer went:
///
/// 1. the paid installer creates the shared directory `2770
///    innerwarden:innerwarden`, setgid, with the operator in that group;
/// 2. a file created here in a group-writable directory is given that
///    directory's group explicitly, which POSIX permits for a member of the
///    group.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewFileOwnership {
    /// Permission bits for a file this product creates.
    pub mode: u32,
    /// The group that file has to carry. `Some` only for a shared directory;
    /// `None` leaves the group exactly as the kernel assigned it.
    pub group: Option<u32>,
}

/// The mode and group [`NewFileOwnership`] describes, for one directory.
#[cfg(unix)]
pub fn new_file_ownership(directory: &Path) -> NewFileOwnership {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    const GROUP_WRITE: u32 = 0o020;
    match fs::metadata(directory) {
        Ok(metadata) if metadata.permissions().mode() & GROUP_WRITE != 0 => NewFileOwnership {
            mode: 0o660,
            group: Some(metadata.gid()),
        },
        _ => NewFileOwnership {
            mode: 0o600,
            group: None,
        },
    }
}

/// Give a just-created file the mode and group [`new_file_ownership`] derives
/// from the directory it lands in.
///
/// Applied through the open descriptor rather than `OpenOptions::mode`, because
/// `mode()` is filtered by the process umask and a hook inherits whatever umask
/// the AI agent that spawned it happened to have. That is not a decision this
/// product gets to make about a file two products share.
///
/// The group is best-effort and the mode is not. Changing a file's group is
/// permitted for a member of the target group and refused otherwise, so an
/// operator who was never added to the `innerwarden` group gets `EPERM` here and
/// no amount of retrying fixes it; failing the write over that would stop the
/// guardrail recording at all, which is worse than recording into a file the
/// agent cannot yet read. The mode is unconditionally ours, so a failure there
/// is a real error.
#[cfg(unix)]
pub fn apply_new_file_ownership(file: &File, directory: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let wanted = new_file_ownership(directory);
    if let Some(group) = wanted.group {
        // Before the mode, because `chown` may clear the set-user-ID and
        // set-group-ID bits, so the mode has to be the last word.
        let _ = std::os::unix::fs::fchown(file, None, Some(group));
    }
    file.set_permissions(fs::Permissions::from_mode(wanted.mode))
}

/// Whose file a replaced file is once the replacement is in place.
///
/// An agent configuration belongs to the person whose agent it configures, so
/// its owner is part of what a replace preserves, and a replace that cannot
/// put it back is refused. A record this product SHARES through a
/// group-writable directory is different: every member of that group already
/// replaces it by renaming over it, and the kernel allows that whoever owns
/// the old file. Refusing the write there protects nobody and stops the
/// recording (see [`when_the_owner_cannot_be_restored`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ownership {
    Preserve,
    SharedRecord,
}

/// A directory several accounts write by design: group-writable, and not
/// sticky. In a sticky directory (`/tmp`) an entry belongs to its owner and
/// nobody else may replace it, so nothing there is shared in this sense.
#[cfg(unix)]
fn is_shared_directory(mode: u32) -> bool {
    const GROUP_WRITE: u32 = 0o020;
    const STICKY: u32 = 0o1000;
    mode & GROUP_WRITE != 0 && mode & STICKY == 0
}

/// Why a replace that could not restore the previous owner is refused.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OwnerRefusal {
    /// An agent configuration: its owner is preserved or the write fails.
    ConfigurationOwnerIsKept,
    /// The restore failed for a reason other than missing privilege, which
    /// keeping the writer as owner would not answer.
    NotAPrivilegeError,
    /// The directory could not be read, so nothing shows it is shared.
    DirectoryUnreadable,
    /// The directory is not writable by its group: only its owner replaces
    /// what is in it, so a different owner must not result from a write.
    DirectoryNotShared,
    /// The directory is sticky: each entry belongs to its owner.
    DirectorySticky,
}

#[cfg(unix)]
impl std::fmt::Display for OwnerRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ConfigurationOwnerIsKept => "the owner of an agent configuration is kept",
            Self::NotAPrivilegeError => "the failure was not a missing privilege",
            Self::DirectoryUnreadable => "its directory could not be read",
            Self::DirectoryNotShared => "its directory is not shared with a group",
            Self::DirectorySticky => "its directory is sticky, so the file is its owner's",
        })
    }
}

/// What a writer that could not give the replacement back to the previous
/// owner does instead. PURE: the facts are handed in.
///
/// THE CASE: `/var/lib/innerwarden/guard/graph.json` is shared, `2770
/// innerwarden:innerwarden`, and the operator records into it through this
/// crate as a member of that group. Once anything running as root rewrote or
/// created it (the paid agent, or `sudo innerwarden-ctl drill`, which ran this
/// CLI as root), it was root's file, and every later write by the operator
/// staged a sibling, asked `fchown(sibling, 0, innerwarden)`, got `EPERM`, and
/// threw the write away. Every decision after that was lost, permanently: no
/// later write could ever succeed, because each one asked for the same
/// impossible owner.
///
/// So in a SHARED directory a writer that may not restore the owner keeps the
/// record as its own, in the directory's group, with the mode it had. That
/// takes nothing from anyone: the same writer could already replace the file
/// by renaming over it, which is what this write does, and the group the other
/// half reads it through is kept. Everywhere else the refusal stands: an agent
/// configuration keeps its owner or is not written, a private directory never
/// hands a file to a different account, and a sticky directory's entries stay
/// their owners'.
#[cfg(unix)]
fn when_the_owner_cannot_be_restored(
    ownership: Ownership,
    restore_errno: Option<i32>,
    directory: Option<(u32, u32)>,
) -> Result<u32, OwnerRefusal> {
    if ownership != Ownership::SharedRecord {
        return Err(OwnerRefusal::ConfigurationOwnerIsKept);
    }
    if restore_errno != Some(libc::EPERM) {
        return Err(OwnerRefusal::NotAPrivilegeError);
    }
    let (mode, group) = directory.ok_or(OwnerRefusal::DirectoryUnreadable)?;
    if mode & 0o1000 != 0 {
        return Err(OwnerRefusal::DirectorySticky);
    }
    if !is_shared_directory(mode) {
        return Err(OwnerRefusal::DirectoryNotShared);
    }
    Ok(group)
}

/// How many times a lock is re-opened when it is found replaced under us.
const LOCK_ATTEMPTS: usize = 4;

struct UpdateLock(File);

impl UpdateLock {
    fn acquire(path: &Path, ownership: Ownership) -> Result<Self, String> {
        let lock_path = sibling(path, "innerwarden.lock");
        for _ in 0..LOCK_ATTEMPTS {
            let file = open_lock(&lock_path, ownership == Ownership::SharedRecord)
                .map_err(|error| format!("opening {}: {error}", lock_path.display()))?;
            // BLOCKING exclusive lock. fs4 1.x renamed `lock_exclusive` to `lock`;
            // both are `flock(LOCK_EX)` on Unix and `LockFileEx(EXCLUSIVE)` on
            // Windows, so this still waits for the other writer instead of failing.
            // Called through the trait so it can never silently resolve to the
            // inherent `std::fs::File::lock` on newer toolchains.
            FileExt::lock(&file)
                .map_err(|error| format!("locking {}: {error}", lock_path.display()))?;
            if lock_still_names(&file, &lock_path) {
                return Ok(Self(file));
            }
        }
        Err(format!(
            "{} kept being replaced while waiting for it",
            lock_path.display()
        ))
    }
}

/// Open the sibling lock for a store in a SHARED directory, the way every
/// writer of that store has to: see [`open_lock`]. Unusable legacy locks there
/// are replaced.
pub fn open_shared_lock(path: &Path) -> std::io::Result<File> {
    open_lock(path, true)
}

/// Whether `file`, a lock just taken, is still the file at `path`.
///
/// A lock that was replaced while this writer waited on it serialises nothing:
/// the next writer opens the new file. The caller re-opens and locks again.
pub fn lock_still_names(file: &File, path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match (file.metadata(), fs::symlink_metadata(path)) {
            (Ok(held), Ok(named)) => held.dev() == named.dev() && held.ino() == named.ino(),
            _ => false,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (file, path);
        true
    }
}

/// Open a lock file, which needs a descriptor and nothing more.
///
/// THREE things about it, all measured on a shared store:
///
/// 1. An existing lock is opened READ-ONLY. `flock` and `LockFileEx` both take
///    a read-only handle, and asking for write access as well meant that a
///    lock somebody else had created (root, through `sudo`, or the paid agent)
///    with the group's read bit and not its write bit refused the operator
///    outright, and every write of the store failed at "opening the lock".
/// 2. A NEW lock takes its mode and group from the directory it lands in, the
///    same rule as every file this product creates ([`new_file_ownership`]):
///    `0660` in the directory's group where that directory is shared, `0600`
///    everywhere else. A hardcoded `0600` lock created by root in the shared
///    directory locked every other account out of it.
/// 3. With `heal`, a lock this account cannot open at all, in a shared
///    directory, is REPLACED by a usable one. Such a lock was left by an older
///    release run as root, and nothing else would ever fix it. Replacing it
///    takes nothing from anyone: every member of the group may already rename
///    over any name in that directory. Root never gets here (it opens
///    anything), and a private directory never heals.
fn open_lock(path: &Path, heal: bool) -> std::io::Result<File> {
    #[cfg(not(unix))]
    let _ = heal;
    match open_existing_lock(path) {
        Ok(file) => return Ok(file),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        #[cfg(unix)]
        Err(error) if heal && error.kind() == std::io::ErrorKind::PermissionDenied => {
            let directory = path.parent().ok_or(error)?;
            replace_unusable_lock(path, directory)?;
            return open_existing_lock(path);
        }
        Err(error) => return Err(error),
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // The directory decides the final mode below; this is only what the
        // file has before that, so it starts private.
        options.mode(0o600);
    }
    innerwarden_safe_io::harden(&mut options);
    match options.open(path) {
        Ok(file) => {
            regular_lock(&file)?;
            #[cfg(unix)]
            if let Some(directory) = path.parent() {
                apply_new_file_ownership(&file, directory)?;
            }
            Ok(file)
        }
        // Another writer created it first: use that one.
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => open_existing_lock(path),
        Err(error) => Err(error),
    }
}

fn open_existing_lock(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    innerwarden_safe_io::harden(&mut options);
    let file = options.open(path)?;
    regular_lock(&file)?;
    Ok(file)
}

fn regular_lock(file: &File) -> std::io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || is_reparse_or_symlink(&metadata) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "lock path is not a regular file",
        ));
    }
    Ok(())
}

/// Replace a lock this account cannot open with a fresh one it can, in a
/// shared directory only. See [`open_lock`].
///
/// The fresh lock is staged under a private name and RENAMED over the old one,
/// so the name is never missing and a link planted there is replaced, never
/// followed. A writer that healed it first wins: if the name opens by the time
/// the replacement is ready, the replacement is discarded.
#[cfg(unix)]
fn replace_unusable_lock(path: &Path, directory: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mode = fs::metadata(directory)?.mode();
    if !is_shared_directory(mode) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "the lock cannot be opened and its directory is not shared",
        ));
    }
    let staged = private_temp(path);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    innerwarden_safe_io::harden(&mut options);
    let file = options.open(&staged)?;
    let prepared = apply_new_file_ownership(&file, directory);
    drop(file);
    if let Err(error) = prepared {
        let _ = fs::remove_file(&staged);
        return Err(error);
    }
    if open_existing_lock(path).is_ok() {
        let _ = fs::remove_file(&staged);
        return Ok(());
    }
    let renamed = fs::rename(&staged, path);
    if renamed.is_err() {
        let _ = fs::remove_file(&staged);
    }
    renamed
}

impl Drop for UpdateLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("config");
    path.with_file_name(format!(".{name}.{suffix}"))
}

fn private_temp(path: &Path) -> PathBuf {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    sibling(path, &format!("{}.{}.tmp", std::process::id(), sequence))
}

fn resolve_target(path: &Path) -> Result<PathBuf, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => fs::canonicalize(path)
            .map_err(|error| format!("resolving symbolic link {}: {error}", path.display())),
        Ok(_) => Ok(path.to_path_buf()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(path.to_path_buf()),
        Err(error) => Err(format!("inspecting {}: {error}", path.display())),
    }
}

fn is_reparse_or_symlink(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn ensure_no_symlink_components(trusted_root: &Path, path: &Path) -> Result<(), String> {
    let relative = path.strip_prefix(trusted_root).map_err(|_| {
        format!(
            "automatic setup path {} is outside its trusted root",
            path.display()
        )
    })?;
    let mut current = trusted_root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(format!(
                "automatic setup path {} contains a non-normal component",
                path.display()
            ));
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if is_reparse_or_symlink(&metadata) => {
                return Err(format!(
                    "automatic setup refuses symbolic links or reparse points in {}",
                    path.display()
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(format!("inspecting {}: {error}", current.display())),
        }
    }
    Ok(())
}

/// Open the config for reading, refusing a symlink.
///
/// This carried `O_NONBLOCK` alone: no `O_NOFOLLOW`, no Windows reparse flag,
/// while the WRITE path forty lines above refused symlinks correctly. The
/// caller then asked `is_reparse_or_symlink` of the opened handle, which cannot
/// catch it: with the link already followed, `File::metadata()` describes the
/// TARGET, so a symlink to any readable file reads back as a plain regular file
/// and is accepted. Reading a config the guard is about to rewrite, through a
/// link somebody else planted, is the case that check was written to stop.
///
/// Now the same shared open as every other site.
fn open_config(path: &Path) -> std::io::Result<File> {
    innerwarden_safe_io::open_no_follow(path)
}

fn regular_config_metadata(file: &File, path: &Path) -> Result<fs::Metadata, String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspecting open {}: {error}", path.display()))?;
    if !metadata.is_file() || is_reparse_or_symlink(&metadata) {
        return Err(format!("{} is not a regular config file", path.display()));
    }
    Ok(metadata)
}

fn current_bytes(path: &Path, limit: u64) -> Result<Option<Vec<u8>>, String> {
    let file = match open_config(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("reading {}: {error}", path.display())),
    };
    let len = regular_config_metadata(&file, path)?.len();
    if len > limit {
        return Err(format!("{} exceeds the size limit", path.display()));
    }
    let mut bytes = Vec::with_capacity(len.try_into().unwrap_or(0));
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("reading {}: {error}", path.display()))?;
    if bytes.len() as u64 > limit {
        return Err(format!("{} grew beyond the size limit", path.display()));
    }
    Ok(Some(bytes))
}

fn current_bytes_no_symlinks(
    trusted_root: &Path,
    path: &Path,
    limit: u64,
) -> Result<Option<Vec<u8>>, String> {
    ensure_no_symlink_components(trusted_root, path)?;
    let opened = innerwarden_safe_io::open_no_follow(path);
    let file = match opened {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("opening {} without links: {error}", path.display())),
    };
    let len = regular_config_metadata(&file, path)?.len();
    if len > limit {
        return Err(format!("{} exceeds the size limit", path.display()));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("reading {}: {error}", path.display()))?;
    if bytes.len() as u64 > limit {
        return Err(format!("{} grew beyond the size limit", path.display()));
    }
    ensure_no_symlink_components(trusted_root, path)?;
    Ok(Some(bytes))
}

/// Read an agent configuration with a fixed upper bound. A missing file is
/// represented by `Ok(None)`; other I/O errors fail closed.
pub fn read_config(path: &Path) -> Result<Option<Vec<u8>>, String> {
    current_bytes(path, MAX_CONFIG_BYTES)
}

/// Read an agent configuration below `trusted_root` with a fixed upper bound,
/// rejecting symlinks and Windows reparse points in every reviewed component.
pub fn read_config_no_symlinks(
    trusted_root: &Path,
    path: &Path,
) -> Result<Option<Vec<u8>>, String> {
    current_bytes_no_symlinks(trusted_root, path, MAX_CONFIG_BYTES)
}

/// Replace `path` without exposing a partially-written file. A file symlink is
/// resolved and its target is replaced, preserving the link (explicit/manual
/// config edits therefore keep working with dotfile managers).
pub fn replace(path: &Path, body: &[u8]) -> Result<(), String> {
    replace_inner(
        path,
        None,
        body,
        true,
        None,
        MAX_CONFIG_BYTES,
        Ownership::Preserve,
    )
}

/// Compare-and-replace variant for read/modify/write operations. `expected`
/// carries the exact bytes read by the caller (`None` means the file was absent).
/// If an editor or agent changes the file before commit, fail and ask for a retry
/// instead of silently losing that concurrent edit.
pub fn replace_if_unchanged(
    path: &Path,
    expected: Option<&[u8]>,
    body: &[u8],
) -> Result<(), String> {
    replace_inner(
        path,
        Some(expected),
        body,
        true,
        None,
        MAX_CONFIG_BYTES,
        Ownership::Preserve,
    )
}

/// Automatic/background variant. Unlike explicit commands, it rejects observed
/// file symlinks/reparse points, opens the final file with no-follow semantics,
/// and rechecks path components immediately before commit. A hostile same-user
/// namespace race is not treated as a separate security boundary.
pub fn replace_if_unchanged_no_symlinks(
    trusted_root: &Path,
    path: &Path,
    expected: Option<&[u8]>,
    body: &[u8],
) -> Result<(), String> {
    replace_inner(
        path,
        Some(expected),
        body,
        false,
        Some(trusted_root),
        MAX_CONFIG_BYTES,
        Ownership::Preserve,
    )
}

/// Same guarantees as [`replace_if_unchanged_no_symlinks`], for a store this
/// product writes itself rather than an agent's configuration file.
///
/// The only difference is the size ceiling. The config ceiling exists to bound
/// what a hostile or broken agent config can make us read; applying it to our
/// own append-heavy graph meant that once the graph crossed 16 MiB every write
/// failed at the verification read, so the pruning that would have brought it
/// back under the limit could never run. Recording stopped for six hours on a
/// real install and said so only on stderr.
pub fn replace_owned_store_no_symlinks(
    trusted_root: &Path,
    path: &Path,
    expected: Option<&[u8]>,
    body: &[u8],
) -> Result<(), String> {
    replace_inner(
        path,
        Some(expected),
        body,
        false,
        Some(trusted_root),
        MAX_OWNED_STORE_BYTES,
        Ownership::SharedRecord,
    )
}

/// Give a staged replacement the previous file's owner and group: the
/// production `fchown`, swapped in tests for one that answers as an
/// unprivileged writer would.
type RestoreOwner = fn(&File, u32, u32) -> std::io::Result<()>;

#[cfg(unix)]
fn restore_owner(file: &File, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: a valid open descriptor and plain integer ids.
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn restore_owner(_file: &File, _uid: u32, _gid: u32) -> std::io::Result<()> {
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn replace_inner(
    requested_path: &Path,
    expected: Option<Option<&[u8]>>,
    body: &[u8],
    follow_file_symlink: bool,
    trusted_root: Option<&Path>,
    limit: u64,
    ownership: Ownership,
) -> Result<(), String> {
    replace_inner_with(
        requested_path,
        expected,
        body,
        follow_file_symlink,
        trusted_root,
        limit,
        ownership,
        restore_owner,
    )
}

#[allow(clippy::too_many_arguments)]
fn replace_inner_with(
    requested_path: &Path,
    expected: Option<Option<&[u8]>>,
    body: &[u8],
    follow_file_symlink: bool,
    trusted_root: Option<&Path>,
    limit: u64,
    ownership: Ownership,
    restore_owner: RestoreOwner,
) -> Result<(), String> {
    let path = if follow_file_symlink {
        resolve_target(requested_path)?
    } else {
        ensure_no_symlink_components(
            trusted_root.ok_or_else(|| "missing automatic setup root".to_string())?,
            requested_path,
        )?;
        requested_path.to_path_buf()
    };
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("creating {}: {error}", parent.display()))?;
    let _lock = UpdateLock::acquire(&path, ownership)?;
    if let Some(expected) = expected {
        let current = if follow_file_symlink {
            current_bytes(&path, limit)?
        } else {
            current_bytes_no_symlinks(
                trusted_root.ok_or_else(|| "missing automatic setup root".to_string())?,
                &path,
                limit,
            )?
        };
        if current.as_deref() != expected {
            return Err(format!(
                "{} changed while InnerWarden was preparing the update; retry",
                requested_path.display()
            ));
        }
    }
    let previous_metadata = match fs::metadata(&path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("inspecting {}: {error}", path.display())),
    };
    let temp = private_temp(&path);
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp)
            .map_err(|error| format!("creating {}: {error}", temp.display()))?;
        if let Some(metadata) = previous_metadata.as_ref() {
            preserve_metadata(&path, &temp, &file, metadata, ownership, restore_owner)?;
        }
        #[cfg(unix)]
        if previous_metadata.is_none() {
            // A file this product is creating, so the directory it lands in
            // decides both its mode and its group. Applied to the sibling temp,
            // which `rename` carries over to the destination unchanged.
            apply_new_file_ownership(&file, parent)
                .map_err(|error| format!("setting ownership on {}: {error}", temp.display()))?;
        }
        file.write_all(body)
            .map_err(|error| format!("writing {}: {error}", temp.display()))?;
        file.sync_all()
            .map_err(|error| format!("syncing {}: {error}", temp.display()))?;
        // CLOSE the staged file before replacing with it.
        //
        // On Unix `rename(2)` does not care that we still hold a descriptor, so
        // this drop looks like tidiness. On Windows it is the difference between
        // working and not: both `ReplaceFileW` and `MoveFileExW` need the
        // replacement file unshared, and an open handle makes them fail with
        // ERROR_SHARING_VIOLATION - "The process cannot access the file because
        // it is being used by another process". That is every config write this
        // product makes: agent policy, MCP wiring, suppression, the graph. The
        // Windows binary has been signed and published since 1.0.0 unable to
        // write its own state, and it stayed invisible because the test suite
        // had never been run on Windows.
        drop(file);

        if !follow_file_symlink {
            ensure_no_symlink_components(
                trusted_root.ok_or_else(|| "missing automatic setup root".to_string())?,
                &path,
            )?;
        }
        // Editors and agent processes do not participate in our advisory lock.
        // Narrow the compare/replace window by comparing again after the temp is
        // fully written and synced. Editors do not share this advisory lock, so
        // an external write in the final syscall window remains a same-user race.
        if let Some(expected) = expected {
            let current = if follow_file_symlink {
                current_bytes(&path, limit)?
            } else {
                current_bytes_no_symlinks(
                    trusted_root.ok_or_else(|| "missing automatic setup root".to_string())?,
                    &path,
                    limit,
                )?
            };
            if current.as_deref() != expected {
                return Err(format!(
                    "{} changed while InnerWarden was preparing the update; retry",
                    requested_path.display()
                ));
            }
        }

        #[cfg(not(windows))]
        {
            fs::rename(&temp, &path)
                .map_err(|error| format!("replacing {}: {error}", path.display()))?;
            // Persist the directory-entry replacement where the platform allows
            // directory fsync; the file contents were synced above.
            let _ = File::open(parent).and_then(|directory| directory.sync_all());
        }

        #[cfg(windows)]
        replace_windows(&path, &temp)?;

        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg_attr(not(unix), allow(unused_variables))]
fn preserve_metadata(
    source: &Path,
    temp: &Path,
    file: &File,
    metadata: &fs::Metadata,
    ownership: Ownership,
    restore_owner: RestoreOwner,
) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if let Err(error) = restore_owner(file, metadata.uid(), metadata.gid()) {
            let directory = source
                .parent()
                .and_then(|directory| fs::metadata(directory).ok())
                .map(|directory| (directory.mode(), directory.gid()));
            let group =
                when_the_owner_cannot_be_restored(ownership, error.raw_os_error(), directory)
                    .map_err(|refusal| {
                        format!(
                            "preserving ownership on {}: {error} ({refusal})",
                            temp.display()
                        )
                    })?;
            // The writer stays the owner. The GROUP is the part the other half
            // reads the record through, so it is not best-effort here: a record
            // that cannot be put in the shared group is refused rather than
            // written where the agent cannot read it.
            let _ = std::os::unix::fs::fchown(file, None, Some(group));
            let landed = file
                .metadata()
                .map_err(|error| format!("inspecting {}: {error}", temp.display()))?;
            if landed.gid() != group {
                return Err(format!(
                    "preserving ownership on {}: {error}, and the replacement could not be \
                     given the shared group {group}",
                    temp.display()
                ));
            }
        }

        #[cfg(target_vendor = "apple")]
        preserve_macos_acl(source, temp, file)?;

        for name in xattr::list(source)
            .map_err(|error| format!("listing attributes on {}: {error}", source.display()))?
        {
            if let Some(value) = xattr::get(source, &name).map_err(|error| {
                format!(
                    "reading attribute {:?} on {}: {error}",
                    name,
                    source.display()
                )
            })? {
                // Some security labels (notably SELinux) are assigned by the
                // filesystem at creation time and cannot be set directly by an
                // unprivileged process. If the sibling temp inherited the exact
                // label already, leave it alone instead of turning a safe update
                // into a spurious permission failure.
                if xattr::get(temp, &name).map_err(|error| {
                    format!(
                        "reading attribute {:?} on {}: {error}",
                        name,
                        temp.display()
                    )
                })? == Some(value.clone())
                {
                    continue;
                }
                xattr::set(temp, &name, &value).map_err(|error| {
                    format!(
                        "preserving attribute {:?} on {}: {error}",
                        name,
                        temp.display()
                    )
                })?;
            }
        }
    }

    file.set_permissions(metadata.permissions())
        .map_err(|error| format!("preserving permissions on {}: {error}", temp.display()))
}

#[cfg(target_vendor = "apple")]
fn preserve_macos_acl(source: &Path, temp: &Path, file: &File) -> Result<(), String> {
    use std::ffi::{c_char, c_int, c_void, CString};
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;

    type Acl = *mut c_void;
    const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;

    unsafe extern "C" {
        fn acl_get_file(path: *const c_char, acl_type: c_int) -> Acl;
        fn acl_init(entries: c_int) -> Acl;
        fn acl_set_fd_np(fd: c_int, acl: Acl, acl_type: c_int) -> c_int;
        fn acl_free(object: *mut c_void) -> c_int;
    }

    let source_c = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| format!("{} contains a NUL byte", source.display()))?;
    let mut acl = unsafe { acl_get_file(source_c.as_ptr(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = std::io::Error::last_os_error();
        // Darwin reports ENOENT when an existing file has no extended ACL.
        // Install an empty ACL on the sibling as well, which also clears any
        // ACL the directory might have caused the new temp to inherit.
        if error.raw_os_error() == Some(libc::ENOENT) && source.exists() {
            acl = unsafe { acl_init(0) };
        }
        if acl.is_null() {
            return Err(format!("reading ACLs on {}: {error}", source.display()));
        }
    }

    let set_result = unsafe { acl_set_fd_np(file.as_raw_fd(), acl, ACL_TYPE_EXTENDED) };
    let set_error = (set_result != 0).then(std::io::Error::last_os_error);
    let free_result = unsafe { acl_free(acl) };
    if let Some(error) = set_error {
        return Err(format!("preserving ACLs on {}: {error}", temp.display()));
    }
    if free_result != 0 {
        return Err(format!(
            "releasing ACL metadata for {}: {}",
            source.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn replace_windows(path: &Path, temp: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, ReplaceFileW, MOVEFILE_WRITE_THROUGH,
    };

    let source: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // ReplaceFile preserves the existing file's ACLs and alternate streams.
    // A new config has no metadata to merge, so MoveFileEx performs the native
    // same-directory atomic move without a remove/rename gap.
    let replaced = if path.exists() {
        unsafe {
            ReplaceFileW(
                destination.as_ptr(),
                source.as_ptr(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                std::ptr::null(),
            )
        }
    } else {
        unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_WRITE_THROUGH,
            )
        }
    };
    if replaced == 0 {
        return Err(format!(
            "replacing {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE TEST THAT WOULD HAVE CAUGHT THE OTHER HALF of spec-052.
    ///
    /// The record both products share lives in `/var/lib/innerwarden/guard/`,
    /// created `2770 innerwarden:innerwarden` with the operator in the group. A
    /// new store created `0600` there is a file the agent still cannot read, and
    /// the symptom is identical to the path being wrong, which is why the first
    /// attempt at this fix looked complete.
    ///
    /// The mode is only half of it; the group is the other half and has its own
    /// test below, because nothing asserted here about mode bits can see it.
    ///
    /// FAILS ON REVERT: restore the hardcoded `from_mode(0o600)` and the shared
    /// case comes back `0600`, invisible to the agent.
    #[cfg(unix)]
    #[test]
    fn a_new_store_takes_the_mode_its_directory_implies() {
        use std::os::unix::fs::PermissionsExt;

        for (directory_mode, expected) in [(0o770, 0o660), (0o700, 0o600), (0o755, 0o600)] {
            let dir = tempfile::TempDir::new().unwrap();
            let shared = dir.path().join("guard");
            std::fs::create_dir(&shared).unwrap();
            std::fs::set_permissions(&shared, fs::Permissions::from_mode(directory_mode)).unwrap();
            let path = shared.join("graph.json");

            replace_owned_store_no_symlinks(&shared, &path, None, b"{}").expect("first write");

            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, expected,
                "a {directory_mode:o} directory must produce a {expected:o} store, got {mode:o}"
            );
        }
    }

    /// A group this process belongs to that is NOT its primary group, so a test
    /// directory can be made to differ from the group the kernel would hand a
    /// new file. Root may hand a file to any group, so the case is always
    /// constructible there.
    #[cfg(unix)]
    fn a_group_this_process_can_hand_to_a_file() -> Option<u32> {
        // SAFETY: both calls only read process credentials, take no pointers,
        // and cannot fail.
        let (primary, root) = unsafe { (libc::getegid(), libc::geteuid() == 0) };
        let mut buffer = [0 as libc::gid_t; 64];
        // SAFETY: the length and the pointer describe `buffer` exactly, and the
        // result is bounded by that length before it is used as one.
        let count = unsafe { libc::getgroups(buffer.len() as libc::c_int, buffer.as_mut_ptr()) };
        if count > 0 {
            if let Some(other) = buffer[..count as usize]
                .iter()
                .copied()
                .find(|group| *group != primary)
            {
                return Some(other);
            }
        }
        root.then(|| primary.wrapping_add(1))
    }

    /// THE HALF THAT NO ASSERTION ABOUT MODE BITS CAN SEE, and it was measured.
    ///
    /// On test001 (Ubuntu 24.04) on 2026-08-28:
    ///
    /// ```text
    /// dir 0770 test001:adm  -> a new file lands test001:test001
    /// dir 2770 test001:adm  -> a new file lands test001:adm
    /// ```
    ///
    /// Linux gives a new file the creator's primary group unless the directory
    /// is setgid. So mode `0660` inside a plain `0770 innerwarden:innerwarden`
    /// directory produces `<operator>:<operator>`, the agent user matches only
    /// OTHER, and OTHER has no bits: the same `graph_absent` dashboard error,
    /// reached by a third route, with every mode assertion still green.
    ///
    /// The directory here is deliberately NOT setgid, because that is the state
    /// this side must survive if the installer did not set it.
    ///
    /// FAILS ON REVERT: drop the `fchown` from [`apply_new_file_ownership`] and
    /// the store lands in this process's own primary group.
    #[cfg(unix)]
    #[test]
    fn a_new_store_in_a_shared_directory_takes_that_directorys_group() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let Some(shared_group) = a_group_this_process_can_hand_to_a_file() else {
            panic!(
                "this machine cannot construct the case: the user running the suite has \
                 exactly one group and is not root, so no directory can be given a group \
                 that differs from the one a new file would get. Add the user to a second \
                 group and re-run; a pass here without this case would prove nothing."
            );
        };

        let dir = tempfile::TempDir::new().unwrap();
        let shared = dir.path().join("guard");
        std::fs::create_dir(&shared).unwrap();
        std::os::unix::fs::chown(&shared, None, Some(shared_group)).expect("chgrp the directory");
        std::fs::set_permissions(&shared, fs::Permissions::from_mode(0o770)).unwrap();
        let directory = fs::metadata(&shared).unwrap();
        assert_eq!(
            directory.gid(),
            shared_group,
            "precondition: the directory is owned by the shared group"
        );
        assert_eq!(
            directory.permissions().mode() & 0o7777,
            0o770,
            "precondition: the directory is NOT setgid, which is the state this side has to survive"
        );

        let path = shared.join("graph.json");
        replace_owned_store_no_symlinks(&shared, &path, None, b"{}").expect("first write");

        let written = fs::metadata(&path).unwrap();
        assert_eq!(
            written.gid(),
            shared_group,
            "the store must carry the shared directory's group, or the agent user \
             matches OTHER and reads nothing"
        );
        assert_eq!(written.permissions().mode() & 0o777, 0o660);
    }

    /// And the SECOND write must not undo the first. Every replacement stages a
    /// fresh sibling and renames it over the destination, and that sibling is a
    /// new file with the creator's own group; without the ownership restore, a
    /// shared store would be readable by the agent exactly once.
    ///
    /// FAILS ON REVERT: drop the `fchown` from `preserve_metadata` and the
    /// second write hands the store back to this process's primary group.
    #[cfg(unix)]
    #[test]
    fn rewriting_a_shared_store_keeps_the_group_the_agent_reads_it_by() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let Some(shared_group) = a_group_this_process_can_hand_to_a_file() else {
            panic!(
                "this machine cannot construct the case: the user running the suite has \
                 exactly one group and is not root. Add the user to a second group and \
                 re-run; a pass here without this case would prove nothing."
            );
        };

        let dir = tempfile::TempDir::new().unwrap();
        let shared = dir.path().join("guard");
        std::fs::create_dir(&shared).unwrap();
        std::os::unix::fs::chown(&shared, None, Some(shared_group)).expect("chgrp the directory");
        std::fs::set_permissions(&shared, fs::Permissions::from_mode(0o770)).unwrap();
        let path = shared.join("graph.json");
        replace_owned_store_no_symlinks(&shared, &path, None, b"{}").expect("first write");
        assert_eq!(
            fs::metadata(&path).unwrap().gid(),
            shared_group,
            "precondition: the first write already put the store in the shared group"
        );

        replace_owned_store_no_symlinks(&shared, &path, Some(b"{}"), b"{\"nodes\":[]}")
            .expect("second write");

        let rewritten = fs::metadata(&path).unwrap();
        assert_eq!(
            rewritten.gid(),
            shared_group,
            "a rewrite must not hand the shared store back to the operator's own group"
        );
        assert_eq!(rewritten.permissions().mode() & 0o777, 0o660);
    }

    /// The other direction, and it is not a formality: a private home must not
    /// be widened because a shared directory needed to be. `0600` is still the
    /// answer for every agent configuration this module writes under a home, and
    /// its group is left exactly as the kernel assigned it.
    #[cfg(unix)]
    #[test]
    fn a_new_config_in_a_private_directory_is_still_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("settings.json");

        assert_eq!(
            new_file_ownership(dir.path()),
            NewFileOwnership {
                mode: 0o600,
                group: None
            },
            "a private directory must not make this product reassign a group"
        );

        replace(&path, b"{}").expect("write");

        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    /// An EXISTING file keeps the mode it has, in a group-writable directory as
    /// everywhere else. The directory decides what a file we create looks like;
    /// it never relitigates one that already exists.
    #[cfg(unix)]
    #[test]
    fn an_existing_store_keeps_its_own_mode_even_in_a_shared_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o770)).unwrap();
        let path = dir.path().join("graph.json");
        fs::write(&path, b"{}").unwrap();
        std::fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();

        replace_owned_store_no_symlinks(dir.path(), &path, Some(b"{}"), b"{\"nodes\":[]}")
            .expect("second write");

        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    /// The mode must be the mode asked for, not the mode minus whatever umask a
    /// hook inherited from the AI agent that spawned it.
    ///
    /// FAILS ON REVERT: set the mode with `OpenOptions::mode` instead of
    /// `set_permissions` and this lands at `0640` under a `0022` umask.
    #[cfg(unix)]
    #[test]
    fn the_umask_of_whoever_spawned_the_hook_does_not_decide_the_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o770)).unwrap();
        let path = dir.path().join("graph.json");

        // SAFETY: umask is per-process state with no memory safety implications;
        // it is restored below before any other test can observe it.
        let previous = unsafe { libc::umask(0o022) };
        let written = replace_owned_store_no_symlinks(dir.path(), &path, None, b"{}");
        // SAFETY: as above, restoring the value this test replaced.
        unsafe { libc::umask(previous) };
        written.expect("write");

        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o660
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_config_reads_reject_fifos_without_waiting_for_a_writer() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("mcp.json");
        let path_c = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path_c.as_ptr(), 0o600) }, 0);

        assert!(read_config(&path).unwrap_err().contains("regular config"));
        assert!(read_config_no_symlinks(dir.path(), &path)
            .unwrap_err()
            .contains("regular config"));
    }

    #[test]
    fn replace_is_complete_and_preserves_permissions() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, b"old").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
            let attribute = if cfg!(target_vendor = "apple") {
                "com.innerwarden.test"
            } else {
                "user.innerwarden.test"
            };
            xattr::set(&path, attribute, b"private").unwrap();
        }
        replace(&path, b"new body").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new body");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o640
            );
            let attribute = if cfg!(target_vendor = "apple") {
                "com.innerwarden.test"
            } else {
                "user.innerwarden.test"
            };
            assert_eq!(
                xattr::get(&path, attribute).unwrap(),
                Some(b"private".to_vec())
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn replace_preserves_macos_acl() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, b"old").unwrap();
        let status = std::process::Command::new("chmod")
            .args(["+a", "everyone deny read"])
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success());

        replace(&path, b"new").unwrap();
        let listing = std::process::Command::new("ls")
            .args(["-le"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(listing.status.success());
        assert!(String::from_utf8_lossy(&listing.stdout).contains("everyone deny read"));
    }

    #[test]
    fn compare_and_replace_rejects_a_concurrent_edit() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, b"first").unwrap();
        let expected = fs::read(&path).unwrap();
        fs::write(&path, b"editor update").unwrap();
        let error =
            replace_if_unchanged(&path, Some(&expected), b"innerwarden update").unwrap_err();
        assert!(error.contains("changed"));
        assert_eq!(fs::read(&path).unwrap(), b"editor update");
    }

    #[cfg(unix)]
    #[test]
    fn update_lock_rejects_symlinks_and_fifos_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::symlink;

        let dir = tempfile::TempDir::new().unwrap();
        let config = dir.path().join("settings.json");
        let lock = sibling(&config, "innerwarden.lock");
        let target = dir.path().join("other.lock");
        fs::write(&target, b"").unwrap();
        symlink(&target, &lock).unwrap();
        assert!(UpdateLock::acquire(&config, Ownership::Preserve).is_err());
        fs::remove_file(&lock).unwrap();

        let fifo = CString::new(lock.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(UpdateLock::acquire(&config, Ownership::Preserve).is_err());
    }

    /// The serialization this module promises is only real if the sibling lock
    /// actually EXCLUDES and actually BLOCKS. A migration that quietly turned it
    /// into a shared lock, a try-lock, or a no-op would still compile and still
    /// pass every other test here, while letting two writers interleave a
    /// read/modify/replace on the same config.
    #[test]
    fn update_lock_excludes_a_second_writer_and_blocks_until_release() {
        use std::sync::mpsc;
        use std::time::Duration;

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        let held = UpdateLock::acquire(&path, Ownership::Preserve).expect("first writer acquires");

        let (acquired_tx, acquired_rx) = mpsc::channel();
        let contender_path = path.clone();
        let contender = std::thread::spawn(move || {
            let lock = UpdateLock::acquire(&contender_path, Ownership::Preserve)
                .expect("second writer acquires");
            acquired_tx.send(()).unwrap();
            drop(lock);
        });

        // Excludes: while the first lock is held the second acquisition cannot
        // complete.
        assert!(
            acquired_rx
                .recv_timeout(Duration::from_millis(250))
                .is_err(),
            "second writer must not acquire while the lock is held"
        );

        // Blocks rather than failing: releasing lets the waiter through instead
        // of it having already returned an error.
        drop(held);
        acquired_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("second writer must acquire once the lock is released");
        contender.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn automatic_replace_rejects_a_file_symlink() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::TempDir::new().unwrap();
        let target = dir.path().join("managed.json");
        let link = dir.path().join("settings.json");
        fs::write(&target, b"old").unwrap();
        symlink(&target, &link).unwrap();
        let error =
            replace_if_unchanged_no_symlinks(dir.path(), &link, Some(b"old"), b"new").unwrap_err();
        assert!(error.contains("refuses symbolic links"));
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(target).unwrap(), b"old");
    }

    #[cfg(unix)]
    #[test]
    fn replace_preserves_a_file_symlink_and_updates_its_target() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::TempDir::new().unwrap();
        let target = dir.path().join("managed.json");
        let link = dir.path().join("settings.json");
        fs::write(&target, b"old").unwrap();
        symlink(&target, &link).unwrap();
        replace(&link, b"new").unwrap();
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(target).unwrap(), b"new");
    }

    // ── a shared record that somebody else last wrote ──────────────────────

    /// What an unprivileged writer gets from `fchown` to another account.
    #[cfg(unix)]
    fn restore_refused(_file: &File, _uid: u32, _gid: u32) -> std::io::Result<()> {
        Err(std::io::Error::from_raw_os_error(libc::EPERM))
    }

    /// A non-root account cannot construct "a file I may not open" for itself
    /// with modes: root opens anything. Said, rather than passed vacuously.
    #[cfg(unix)]
    fn require_unprivileged(test: &str) {
        // SAFETY: reads the process credentials, cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            panic!(
                "{test}: running as root, which ignores file modes, so the case cannot be \
                 constructed. Run the suite as an ordinary account; a pass here would prove \
                 nothing."
            );
        }
    }

    #[cfg(unix)]
    fn shared_dir_with_mode(mode: u32) -> (tempfile::TempDir, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        let shared = dir.path().join("guard");
        fs::create_dir(&shared).unwrap();
        if let Some(group) = a_group_this_process_can_hand_to_a_file() {
            // A group that is not this process's primary one, so "the record
            // carries the directory's group" cannot hold by accident.
            let _ = std::os::unix::fs::chown(&shared, None, Some(group));
        }
        fs::set_permissions(&shared, fs::Permissions::from_mode(mode)).unwrap();
        (dir, shared)
    }

    /// THE DEFECT, decision half. Every refusal is a different reason, and the
    /// only shape that keeps the writer as owner is a shared record, a missing
    /// privilege, and a group-writable directory that is not sticky.
    #[cfg(unix)]
    #[test]
    fn only_a_shared_record_in_a_shared_directory_changes_hands() {
        const SHARED: (u32, u32) = (0o2770, 986);
        assert_eq!(
            when_the_owner_cannot_be_restored(
                Ownership::SharedRecord,
                Some(libc::EPERM),
                Some(SHARED)
            ),
            Ok(986),
            "the shared record is kept writable, in the directory's group"
        );
        assert_eq!(
            when_the_owner_cannot_be_restored(
                Ownership::SharedRecord,
                Some(libc::EPERM),
                Some((0o770, 986))
            ),
            Ok(986),
            "setgid or not, a group-writable directory is shared"
        );
        assert_eq!(
            when_the_owner_cannot_be_restored(Ownership::Preserve, Some(libc::EPERM), Some(SHARED)),
            Err(OwnerRefusal::ConfigurationOwnerIsKept),
            "an agent configuration keeps its owner or is not written, wherever it is"
        );
        assert_eq!(
            when_the_owner_cannot_be_restored(
                Ownership::SharedRecord,
                Some(libc::EIO),
                Some(SHARED)
            ),
            Err(OwnerRefusal::NotAPrivilegeError)
        );
        assert_eq!(
            when_the_owner_cannot_be_restored(Ownership::SharedRecord, None, Some(SHARED)),
            Err(OwnerRefusal::NotAPrivilegeError)
        );
        assert_eq!(
            when_the_owner_cannot_be_restored(Ownership::SharedRecord, Some(libc::EPERM), None),
            Err(OwnerRefusal::DirectoryUnreadable)
        );
        for private in [0o700, 0o750, 0o755, 0o2750] {
            assert_eq!(
                when_the_owner_cannot_be_restored(
                    Ownership::SharedRecord,
                    Some(libc::EPERM),
                    Some((private, 986))
                ),
                Err(OwnerRefusal::DirectoryNotShared),
                "a {private:o} directory is its owner's: a file there never changes hands"
            );
        }
        for sticky in [0o1777, 0o1770, 0o3770] {
            assert_eq!(
                when_the_owner_cannot_be_restored(
                    Ownership::SharedRecord,
                    Some(libc::EPERM),
                    Some((sticky, 986))
                ),
                Err(OwnerRefusal::DirectorySticky),
                "a {sticky:o} directory keeps each entry its owner's"
            );
        }
    }

    /// THE DEFECT, as the operator met it: the shared graph belonged to root,
    /// the operator's write could not give it back, and the write was thrown
    /// away. Now it lands, owned by the writer, in the directory's group, with
    /// the mode it had.
    ///
    /// FAILS ON REVERT: make `preserve_metadata` return the `fchown` error
    /// again and this write is refused, as every one was on the demo host.
    #[cfg(unix)]
    #[test]
    fn a_shared_record_another_account_owns_is_still_written() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let (_dir, shared) = shared_dir_with_mode(0o770);
        let path = shared.join("graph.json");
        fs::write(&path, b"{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();

        replace_inner_with(
            &path,
            Some(Some(b"{}")),
            b"{\"nodes\":[1]}",
            false,
            Some(&shared),
            MAX_OWNED_STORE_BYTES,
            Ownership::SharedRecord,
            restore_refused,
        )
        .expect("a shared record must still be written when its owner cannot be restored");

        assert_eq!(fs::read(&path).unwrap(), b"{\"nodes\":[1]}");
        let written = fs::metadata(&path).unwrap();
        // SAFETY: reads the process credentials, cannot fail.
        assert_eq!(
            written.uid(),
            unsafe { libc::geteuid() },
            "the writer owns it"
        );
        assert_eq!(
            written.gid(),
            fs::metadata(&shared).unwrap().gid(),
            "it stays in the shared group the other half reads it through"
        );
        assert_eq!(
            written.permissions().mode() & 0o7777,
            0o640,
            "with the mode it had"
        );
    }

    /// The same failure on an agent CONFIGURATION is still a refusal, for the
    /// reason that names it, and the file is untouched: a writer must not end
    /// up owning somebody else's configuration because a directory was shared.
    #[cfg(unix)]
    #[test]
    fn a_configuration_another_account_owns_is_still_refused() {
        let (_dir, shared) = shared_dir_with_mode(0o770);
        let path = shared.join("settings.json");
        fs::write(&path, b"{}").unwrap();

        let error = replace_inner_with(
            &path,
            Some(Some(b"{}")),
            b"{\"hooks\":[]}",
            false,
            Some(&shared),
            MAX_CONFIG_BYTES,
            Ownership::Preserve,
            restore_refused,
        )
        .expect_err("a configuration keeps its owner or is not written");
        assert!(
            error.ends_with(&format!("({})", OwnerRefusal::ConfigurationOwnerIsKept)),
            "refused for the wrong reason: {error}"
        );
        assert_eq!(fs::read(&path).unwrap(), b"{}");
    }

    /// And a record outside a shared directory never changes hands: the
    /// refusal, its reason, and the file left as it was.
    #[cfg(unix)]
    #[test]
    fn a_record_in_a_private_or_sticky_directory_never_changes_hands() {
        for (mode, reason) in [
            (0o755, OwnerRefusal::DirectoryNotShared),
            (0o1770, OwnerRefusal::DirectorySticky),
        ] {
            let (_dir, shared) = shared_dir_with_mode(mode);
            let path = shared.join("graph.json");
            fs::write(&path, b"{}").unwrap();

            let error = replace_inner_with(
                &path,
                Some(Some(b"{}")),
                b"{\"nodes\":[1]}",
                false,
                Some(&shared),
                MAX_OWNED_STORE_BYTES,
                Ownership::SharedRecord,
                restore_refused,
            )
            .expect_err("only a shared directory hands a record to its writer");
            assert!(
                error.ends_with(&format!("({reason})")),
                "{mode:o}: refused for the wrong reason: {error}"
            );
            assert_eq!(fs::read(&path).unwrap(), b"{}");
        }
    }

    /// A lock somebody else created, readable by this account and not
    /// writable, still serialises. `flock` needs a descriptor, not write
    /// access; asking for write as well refused the operator outright.
    ///
    /// FAILS ON REVERT: open the existing lock read-write again and the write
    /// fails at "opening the lock".
    #[cfg(unix)]
    #[test]
    fn a_lock_this_account_may_only_read_still_serialises_the_write() {
        use std::os::unix::fs::PermissionsExt;
        require_unprivileged("a_lock_this_account_may_only_read_still_serialises_the_write");
        // Where no lock is ever replaced (a private directory, and an agent
        // configuration anywhere), so only the read-only open can make this
        // pass.
        let private = tempfile::TempDir::new().unwrap();
        fs::set_permissions(private.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let (_dir, shared) = shared_dir_with_mode(0o770);
        for (root, path, shared_record) in [
            (private.path(), private.path().join("graph.json"), true),
            (shared.as_path(), shared.join("settings.json"), false),
        ] {
            let lock = sibling(&path, "innerwarden.lock");
            fs::write(&lock, b"").unwrap();
            fs::set_permissions(&lock, fs::Permissions::from_mode(0o440)).unwrap();
            assert!(
                OpenOptions::new().write(true).open(&lock).is_err(),
                "precondition: this account may not write the lock"
            );

            let written = if shared_record {
                replace_owned_store_no_symlinks(root, &path, None, b"{}")
            } else {
                replace_if_unchanged_no_symlinks(root, &path, None, b"{}")
            };
            written.unwrap_or_else(|error| {
                panic!(
                    "a readable lock is all a lock needs, at {}: {error}",
                    lock.display()
                )
            });

            let ownership = if shared_record {
                Ownership::SharedRecord
            } else {
                Ownership::Preserve
            };
            let held = UpdateLock::acquire(&path, ownership).expect("held");
            assert!(
                FileExt::try_lock(&open_existing_lock(&lock).unwrap()).is_err(),
                "and it still EXCLUDES: a second descriptor cannot take it"
            );
            drop(held);
        }
    }

    /// A new lock in the shared directory is one every member of the group can
    /// open, whoever made it. A hardcoded `0600` lock made by root there shut
    /// the operator out of the store for good.
    ///
    /// FAILS ON REVERT: create the lock with a fixed `0600` again.
    #[cfg(unix)]
    #[test]
    fn a_new_lock_in_a_shared_directory_is_one_the_group_can_open() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let (_dir, shared) = shared_dir_with_mode(0o770);
        let path = shared.join("graph.json");

        replace_owned_store_no_symlinks(&shared, &path, None, b"{}").expect("write");

        let lock = fs::metadata(sibling(&path, "innerwarden.lock")).unwrap();
        assert_eq!(lock.permissions().mode() & 0o777, 0o660);
        assert_eq!(lock.gid(), fs::metadata(&shared).unwrap().gid());

        // A private directory keeps its private lock.
        let private = tempfile::TempDir::new().unwrap();
        fs::set_permissions(private.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let config = private.path().join("settings.json");
        replace(&config, b"{}").expect("write");
        assert_eq!(
            fs::metadata(sibling(&config, "innerwarden.lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    /// A lock this account cannot open AT ALL, left in the shared directory by
    /// an older release run as root, is replaced by one it can, so recording
    /// resumes instead of failing forever. Only there: in a private directory,
    /// or for an agent configuration, the refusal stands.
    ///
    /// FAILS ON REVERT: drop the heal from `open_lock` and the shared write
    /// fails at "opening the lock".
    #[cfg(unix)]
    #[test]
    fn an_unusable_lock_in_a_shared_directory_is_replaced_and_nowhere_else() {
        use std::os::unix::fs::PermissionsExt;
        require_unprivileged("an_unusable_lock_in_a_shared_directory_is_replaced_and_nowhere_else");
        let plant = |dir: &Path, name: &str| -> PathBuf {
            let path = dir.join(name);
            let lock = sibling(&path, "innerwarden.lock");
            fs::write(&lock, b"").unwrap();
            fs::set_permissions(&lock, fs::Permissions::from_mode(0o000)).unwrap();
            assert!(
                open_existing_lock(&lock).is_err(),
                "precondition: this account cannot open the planted lock"
            );
            path
        };

        let (_dir, shared) = shared_dir_with_mode(0o770);
        let path = plant(&shared, "graph.json");
        replace_owned_store_no_symlinks(&shared, &path, None, b"{}")
            .expect("the shared record is written past an unusable legacy lock");
        assert_eq!(fs::read(&path).unwrap(), b"{}");
        assert_eq!(
            fs::metadata(sibling(&path, "innerwarden.lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o660,
            "the replacement is one the whole group can open"
        );

        let config = plant(&shared, "settings.json");
        assert!(
            replace_if_unchanged_no_symlinks(&shared, &config, None, b"{}").is_err(),
            "an agent configuration's lock is never replaced"
        );
        assert!(!config.exists());

        let private = tempfile::TempDir::new().unwrap();
        fs::set_permissions(private.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let store = plant(private.path(), "graph.json");
        assert!(
            replace_owned_store_no_symlinks(private.path(), &store, None, b"{}").is_err(),
            "a private directory never heals a lock"
        );
        assert!(!store.exists());
    }
}

#[cfg(all(test, unix))]
mod symlink_read_regression {
    use super::*;

    /// The config READ path refuses a symlink.
    ///
    /// It did not. `open_config` carried `O_NONBLOCK` alone while the write
    /// path forty lines above refused links correctly, and the
    /// `is_reparse_or_symlink` check that was supposed to cover it asked the
    /// question of an already-followed handle, where the answer describes the
    /// target. So a link planted at the config path was read.
    ///
    /// FAILS ON REVERT: give `open_config` its own `OpenOptions` with only
    /// `O_NONBLOCK` again.
    #[test]
    fn a_symlinked_config_is_not_read() {
        let dir = std::env::temp_dir().join(format!("iw-cfg-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tempdir");

        let target = dir.join("elsewhere");
        std::fs::write(&target, b"not-your-config\n").expect("write target");
        let link = dir.join("config.toml");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let err = open_config(&link).expect_err("a symlinked config must not open");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ELOOP),
            "expected the open itself to refuse the link, got {err:?}"
        );

        // And a real file at the same path still opens, so this is a link
        // refusal and not a broken read path.
        std::fs::remove_file(&link).expect("unlink");
        std::fs::write(&link, b"real = true\n").expect("write real config");
        open_config(&link).expect("a regular config must still open");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
