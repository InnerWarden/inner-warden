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

struct UpdateLock(File);

impl UpdateLock {
    fn acquire(path: &Path) -> Result<Self, String> {
        let lock_path = sibling(path, "innerwarden.lock");
        let file = open_lock_file(&lock_path)
            .map_err(|error| format!("opening {}: {error}", lock_path.display()))?;
        file.lock_exclusive()
            .map_err(|error| format!("locking {}: {error}", lock_path.display()))?;
        Ok(Self(file))
    }
}

fn open_lock_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || is_reparse_or_symlink(&metadata) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "lock path is not a regular file",
        ));
    }
    Ok(file)
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

fn open_config(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    options.open(path)
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
    let opened = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path)
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            OpenOptions::new()
                .read(true)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)
        }
        #[cfg(not(any(unix, windows)))]
        {
            OpenOptions::new().read(true).open(path)
        }
    };
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
    replace_inner(path, None, body, true, None, MAX_CONFIG_BYTES)
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
    replace_inner(path, Some(expected), body, true, None, MAX_CONFIG_BYTES)
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
    )
}

fn replace_inner(
    requested_path: &Path,
    expected: Option<Option<&[u8]>>,
    body: &[u8],
    follow_file_symlink: bool,
    trusted_root: Option<&Path>,
    limit: u64,
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
    let _lock = UpdateLock::acquire(&path)?;
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
            preserve_metadata(&path, &temp, &file, metadata)?;
        }
        #[cfg(unix)]
        if previous_metadata.is_none() {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|error| {
                    format!("setting private permissions on {}: {error}", temp.display())
                })?;
        }
        file.write_all(body)
            .map_err(|error| format!("writing {}: {error}", temp.display()))?;
        file.sync_all()
            .map_err(|error| format!("syncing {}: {error}", temp.display()))?;

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
) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;

        if unsafe { libc::fchown(file.as_raw_fd(), metadata.uid(), metadata.gid()) } != 0 {
            return Err(format!(
                "preserving ownership on {}: {}",
                temp.display(),
                std::io::Error::last_os_error()
            ));
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
        assert!(UpdateLock::acquire(&config).is_err());
        fs::remove_file(&lock).unwrap();

        let fifo = CString::new(lock.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(UpdateLock::acquire(&config).is_err());
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
}
