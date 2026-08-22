//! Opening a file without following a symlink into somewhere else.
//!
//! This pattern was hand-copied into three crates: `agent-guard/file_update.rs`
//! (twice), `cli/agent_policy.rs` (twice) and `dashboard-kit/token_usage.rs`.
//! Five copies of a security-critical open, and by the time the 2026-08-22 audit
//! looked, one of them had already drifted.
//!
//! The drifted one is worth stating, because it is what a fourth copy would do
//! next. `agent-guard`'s `open_config` opened its file with `O_NONBLOCK` alone,
//! no `O_NOFOLLOW` and no Windows reparse flag, and then called
//! `is_reparse_or_symlink` on the OPENED handle to reject links. That check
//! cannot work: with the link already followed, `File::metadata()` describes the
//! TARGET, so a symlink to any readable file reads as a plain regular file and
//! is accepted. The write path in the same file refused symlinks correctly. The
//! read path did not, and the two sat forty lines apart.
//!
//! ## What is preserved
//!
//! - `O_NOFOLLOW`: the open itself fails on a symlink, rather than succeeding
//!   and being second-guessed afterwards.
//! - `O_NONBLOCK`: opening a FIFO must not hang the process. Without it, a
//!   named pipe in place of a config file is a denial of service that needs no
//!   privileges to plant.
//! - `FILE_FLAG_OPEN_REPARSE_POINT` on Windows: opens the reparse point itself
//!   instead of traversing it, which is that platform's equivalent.
//! - The post-open check on the returned handle stays the caller's job where it
//!   already exists, and remains meaningful, because with `O_NOFOLLOW` the
//!   handle really is the named file.
//!
//! ## What is deliberately not here
//!
//! No `O_CREAT`, no mode, no truncation policy. Those differ per call site for
//! real reasons (the update path creates with `0o600`, the read paths must not
//! create at all), and folding them in would produce one function with four
//! booleans, which is how a shared helper becomes worse than the copies.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

/// Windows: open the reparse point rather than traversing it.
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// Apply the symlink-safe flags to an `OpenOptions` the caller has already
/// configured for read/write/create.
///
/// Exposed separately from [`open_no_follow`] because the update path needs to
/// set `mode(0o600)` and `create(true)` on the same builder, and a helper that
/// owned the whole builder would force that call site to keep its own copy,
/// which is the situation this crate exists to end.
pub fn harden(options: &mut OpenOptions) -> &mut OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NOFOLLOW: refuse a symlink at open time.
        // O_NONBLOCK: a FIFO here must not hang us.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options
}

/// Open an existing file for reading, refusing symlinks.
///
/// Does not create. A read path that creates its own input is a read path that
/// can be steered by whoever wins the race to the empty file.
pub fn open_no_follow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    harden(&mut options);
    options.open(path)
}

/// Whether an already-open handle is something other than a plain regular file.
///
/// Kept as a second line after `O_NOFOLLOW` rather than instead of it. On a
/// handle opened with `O_NOFOLLOW` this is a real check on the named file; on a
/// handle opened without it, it describes whatever the link pointed at, which is
/// exactly how the drifted copy passed while following links.
pub fn is_regular_file(metadata: &std::fs::Metadata) -> bool {
    metadata.is_file() && !is_reparse_or_symlink(metadata)
}

/// Symlink on unix, reparse point on Windows.
pub fn is_reparse_or_symlink(metadata: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    metadata.file_type().is_symlink()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn tmpdir() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "iw-safe-io-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("tempdir");
        p
    }

    #[test]
    fn a_plain_file_opens() {
        let dir = tmpdir();
        let f = dir.join("real.toml");
        std::fs::File::create(&f)
            .expect("create")
            .write_all(b"x = 1\n")
            .expect("write");

        let opened = open_no_follow(&f).expect("a regular file must open");
        assert!(is_regular_file(&opened.metadata().expect("metadata")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The whole point. A symlink must fail at OPEN, not be caught afterwards.
    ///
    /// FAILS ON REVERT: drop `O_NOFOLLOW` from `harden` and this open succeeds,
    /// which is the state `agent-guard::open_config` shipped in.
    #[cfg(unix)]
    #[test]
    fn a_symlink_is_refused_at_open() {
        let dir = tmpdir();
        let target = dir.join("secret");
        std::fs::File::create(&target)
            .expect("create")
            .write_all(b"sensitive\n")
            .expect("write");
        let link = dir.join("config.toml");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let err = open_no_follow(&link).expect_err("a symlink must not open");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ELOOP),
            "expected ELOOP from O_NOFOLLOW, got {err:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// And the reason the post-open check alone is not enough: through a
    /// followed symlink the metadata describes the target, so the check that
    /// was supposed to reject links sees a regular file.
    #[cfg(unix)]
    #[test]
    fn metadata_on_a_followed_link_cannot_see_the_link() {
        let dir = tmpdir();
        let target = dir.join("secret");
        std::fs::File::create(&target).expect("create");
        let link = dir.join("config.toml");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        // Open WITHOUT hardening, the way the drifted copy did.
        let weak = OpenOptions::new().read(true).open(&link).expect("follows");
        let md = weak.metadata().expect("metadata");
        assert!(
            is_regular_file(&md),
            "this is the trap: the drifted copy asked this question of a handle \
             that had already followed the link, and got 'regular file' back"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A FIFO must not hang the caller.
    #[cfg(unix)]
    #[test]
    fn a_fifo_does_not_block_the_open() {
        let dir = tmpdir();
        let fifo = dir.join("config.toml");
        let c = std::ffi::CString::new(fifo.to_string_lossy().as_bytes()).expect("cstring");
        // SAFETY: `c` is a valid NUL-terminated path for the lifetime of the
        // call, and mkfifo only creates a filesystem entry.
        let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
        if rc != 0 {
            let _ = std::fs::remove_dir_all(&dir);
            return; // filesystem without FIFO support; nothing to assert
        }

        // Without O_NONBLOCK this open blocks until a writer appears, and the
        // test would hang rather than fail, which is the same thing a host
        // would do.
        let opened = open_no_follow(&fifo);
        match opened {
            Ok(f) => assert!(
                !is_regular_file(&f.metadata().expect("metadata")),
                "a FIFO is not a regular file and the caller must be able to see that"
            ),
            Err(e) => assert_ne!(
                e.kind(),
                std::io::ErrorKind::TimedOut,
                "the open must return, not hang: {e:?}"
            ),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `harden` composes with a builder the caller has already configured.
    #[test]
    fn harden_leaves_the_callers_own_options_intact() {
        let dir = tmpdir();
        let f = dir.join("created.toml");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        harden(&mut options);
        let file = options.open(&f).expect("create through a hardened builder");
        assert!(is_regular_file(&file.metadata().expect("metadata")));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
