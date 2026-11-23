//! The Landlock scope a Linux jail's command starts under: no `connect`, and
//! no datagram sent, to an abstract unix socket made outside the jail.
//!
//! The jail shares the host's network namespace (the agent, its hook and git
//! need it), and an abstract unix socket (`@name`, no file behind it) lives in
//! the network namespace, not in the file system the jail hides. So without
//! this a program in the jail reached every abstract socket of the person's
//! session: an X server's (`@/tmp/.X11-unix/X0`), where the display lets the
//! local user in, took keystrokes typed into the person's terminal. The
//! seccomp filter cannot refuse it: it sees the pointer to the address, never
//! the address.
//!
//! Landlock scopes it (`LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET`, ABI 6, Linux
//! 6.12): a process in the domain may connect only to an abstract socket made
//! by a process in the same domain or one nested in it. A socket the jail's
//! programs make themselves still works, and nothing else changes: no file
//! access and no network port is handled by the domain, so TCP, UDP and
//! unix sockets reached by a path (the launcher's record channel, the
//! system's resolver) are as they were.
//!
//! The launcher's own binary, shown read-only in the jail, applies it as the
//! jail's command ([`crate::contain::launch::exec_child`]) and then
//! replaces itself with the command, so every program the command starts is
//! in the domain. bubblewrap has set `no_new_privs` by then; it is set again
//! here, as Landlock asks for it.

// Only a Linux jail starts through this; elsewhere the pure parts are
// built for their tests alone.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

/// `LANDLOCK_CREATE_RULESET_VERSION`: asked with no ruleset, the call answers
/// the highest Landlock ABI this kernel runs.
#[cfg(target_os = "linux")]
const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;

/// `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` (`include/uapi/linux/landlock.h`).
#[cfg(target_os = "linux")]
const LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1;

/// The first Landlock ABI with scopes (Linux 6.12).
pub const SCOPE_ABI: i64 = 6;

/// `struct landlock_ruleset_attr` as ABI 6 lays it out. No file access and no
/// network port is handled, only the scope.
#[cfg(target_os = "linux")]
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

/// What the kernel takes, by its answer to the version question: an ABI, or
/// an error (`EOPNOTSUPP`: built in and not turned on; `ENOSYS`: not built).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kernel {
    /// The kernel runs Landlock with scopes.
    Scopes,
    /// It does not: no Landlock, or one older than ABI 6.
    NoScopes,
}

/// PURE. Whether a kernel that answered `abi` to the version question
/// (`None` for an error) scopes abstract unix sockets.
pub fn kernel_from_abi(abi: Option<i64>) -> Kernel {
    match abi {
        Some(v) if v >= SCOPE_ABI => Kernel::Scopes,
        _ => Kernel::NoScopes,
    }
}

/// What the jail's command is told, on stderr, where the kernel cannot keep
/// it from the session's abstract sockets. The command still starts: a jail
/// on such a kernel is what it was before.
pub const NO_SCOPES_SAID: &str =
    "innerwarden contain: this kernel cannot keep the jail's programs \
     from abstract unix sockets made outside it, an X server's among them (Landlock with \
     abstract socket scoping needs Linux 6.12 or later with landlock in the LSM list); \
     the jail runs without that rule.";

/// The highest Landlock ABI this kernel runs, `None` where it runs none.
#[cfg(target_os = "linux")]
pub fn landlock_abi() -> Option<i64> {
    // SAFETY: the version question reads no ruleset (a null pointer and a
    // size of 0 are what the kernel asks for with this flag).
    let v = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    (v >= 0).then_some(v)
}

/// Put this process (its calling thread, before `exec`) under the scope.
/// `Ok(Kernel::NoScopes)` where the kernel has none, and nothing changes;
/// an error where the kernel has them and still refused, which the caller
/// treats as a jail it cannot build.
#[cfg(target_os = "linux")]
pub fn close_abstract_sockets() -> std::io::Result<Kernel> {
    use std::os::fd::{FromRawFd, OwnedFd};
    if kernel_from_abi(landlock_abi()) == Kernel::NoScopes {
        return Ok(Kernel::NoScopes);
    }
    let attr = RulesetAttr {
        handled_access_fs: 0,
        handled_access_net: 0,
        scoped: LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET,
    };
    // SAFETY: `attr` lives until the call returns, and its size is the one
    // given.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const RulesetAttr,
            std::mem::size_of::<RulesetAttr>(),
            0 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the kernel just made this descriptor for us; it is ours alone.
    let ruleset = unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) };
    // SAFETY: `prctl` with these arguments only sets this thread's flag.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    use std::os::fd::AsRawFd;
    // SAFETY: the descriptor is a ruleset the kernel made; flags 0.
    let restricted = unsafe {
        libc::syscall(
            libc::SYS_landlock_restrict_self,
            ruleset.as_raw_fd(),
            0 as libc::c_uint,
        )
    };
    if restricted != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(Kernel::Scopes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ABI 6 is the first with scopes; an error or an older ABI has none.
    ///
    /// FAILS ON REVERT: take ABI 5 (Linux 6.10, no scopes) as one that has
    /// them, or an error as one.
    #[test]
    fn only_abi_6_and_later_scope_abstract_sockets() {
        assert_eq!(kernel_from_abi(None), Kernel::NoScopes);
        for old in [0, 1, 4, 5] {
            assert_eq!(kernel_from_abi(Some(old)), Kernel::NoScopes, "{old}");
        }
        for new in [6, 7, 9] {
            assert_eq!(kernel_from_abi(Some(new)), Kernel::Scopes, "{new}");
        }
    }

    /// The words said on an older kernel never use "scope" alone: the jail
    /// tests read that word as the word of a systemd scope.
    #[test]
    fn what_an_older_kernel_is_told_names_the_x_server_and_the_kernel() {
        let flat = NO_SCOPES_SAID
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(flat.contains("an X server's among them"), "{flat}");
        assert!(flat.contains("Linux 6.12 or later"), "{flat}");
        assert!(flat.contains("the jail runs without that rule"), "{flat}");
        assert!(!flat.contains(" scope "), "{flat}");
        assert!(!flat.contains('\u{2014}'), "{flat}");
    }

    /// The struct the kernel reads: three u64, 24 bytes.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_ruleset_attr_is_laid_out_as_abi_6() {
        assert_eq!(std::mem::size_of::<RulesetAttr>(), 24);
    }
}
