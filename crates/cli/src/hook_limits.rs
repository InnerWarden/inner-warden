//! The resource limits the hook is started with.
//!
//! Limits lowered on the agent (`prlimit --pid` on its process, `ulimit` in
//! the shell that starts it) are inherited by every hook the agent starts.
//! A process that writes past its soft `RLIMIT_FSIZE` is sent `SIGXFSZ`,
//! whose default action ends it: the hook then died at the first record it
//! appended past the limit, before it answered, with empty stdout and no exit
//! code, which the agent reads as a hook that failed and runs the call
//! unscreened. `SIGXCPU` at the soft `RLIMIT_CPU` has the same default.
//!
//! Measured 2026-11-26 with release binaries on a disposable home, each limit
//! set in the child before exec:
//!
//! - a soft `RLIMIT_DATA` of 1 to 4 MiB, a soft `RLIMIT_NOFILE` of 4 and a
//!   soft `RLIMIT_STACK` of 24 to 32 KiB made the hook fail inside (an
//!   allocation, the policy file it could not open, a stack it could not
//!   grow) and refuse every call, `ls -la` included;
//! - none of them, nor a CPU limit of a second or more, ended it by a signal
//!   once it was running (it uses about 10 ms of CPU).
//!
//! The hook ignores both signals and raises each of these soft limits (and
//! `RLIMIT_AS`) to the hard one before it does anything else; the open file
//! and stack limits only up to the usual defaults, so what the hook starts
//! does not inherit a far larger limit than it would have had. A write the
//! hard limit still refuses then fails with an error (`EFBIG`) the writer
//! already handles as a lost record, and the verdict is answered as on any
//! other call; a hard data, file or stack limit too low for the hook still
//! refuses the call. The signals stay ignored in what the hook starts, which
//! then gets the same error instead of dying.
//!
//! What no code in the hook can lift, because the process ends before its
//! first instruction (measured the same way): a CPU limit of 0 (`SIGXCPU`
//! at once, or `SIGKILL` when the hard limit is 0 too), an address space of
//! 16 MiB (the binary does not map), three open files (the loader cannot
//! open the shared libraries, exit 127) and, one start in three, a 16 KiB
//! stack. The guard refuses lowering the agent's limits for that reason.

/// Keep lowered resource limits from killing or crippling the hook. Called
/// first thing on the hook's way in; nothing to do off Unix.
pub(crate) fn keep_limits_from_killing_the_hook() {
    #[cfg(unix)]
    unix::lift();
}

#[cfg(unix)]
mod unix {
    /// The usual soft limit of open files on Linux.
    const OPEN_FILES: libc::rlim_t = 1024;
    /// The usual soft stack limit on Linux and macOS (8 MiB).
    const STACK: libc::rlim_t = 8 * 1024 * 1024;

    /// The type a resource is named by in `getrlimit` and `setrlimit`.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    type Resource = libc::__rlimit_resource_t;
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    type Resource = libc::c_int;

    /// Each limit and the most its soft value is raised to (the hard limit
    /// caps it); `RLIM_INFINITY` means up to the hard limit.
    const LIMITS: [(Resource, libc::rlim_t); 6] = [
        (libc::RLIMIT_FSIZE, libc::RLIM_INFINITY),
        (libc::RLIMIT_CPU, libc::RLIM_INFINITY),
        (libc::RLIMIT_AS, libc::RLIM_INFINITY),
        (libc::RLIMIT_DATA, libc::RLIM_INFINITY),
        (libc::RLIMIT_NOFILE, OPEN_FILES),
        (libc::RLIMIT_STACK, STACK),
    ];

    /// The soft value a limit is raised to: up to `most`, never past the
    /// hard limit, never below where it already is.
    pub(super) fn raised(
        soft: libc::rlim_t,
        hard: libc::rlim_t,
        most: libc::rlim_t,
    ) -> libc::rlim_t {
        let target = most.min(hard);
        if soft == libc::RLIM_INFINITY || soft >= target {
            soft
        } else {
            target
        }
    }

    pub(super) fn lift() {
        // SAFETY: SIG_IGN is a valid disposition for SIGXFSZ and SIGXCPU,
        // set before any thread of the hook is started.
        unsafe {
            libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
            libc::signal(libc::SIGXCPU, libc::SIG_IGN);
        }
        for (resource, most) in LIMITS {
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: `limit` is a valid rlimit the call fills.
            if unsafe { libc::getrlimit(resource, &mut limit) } != 0 {
                continue;
            }
            let soft = raised(limit.rlim_cur, limit.rlim_max, most);
            if soft != limit.rlim_cur {
                limit.rlim_cur = soft;
                // SAFETY: a soft limit at or below the hard one is always
                // allowed; a failure leaves the limit as it was.
                unsafe {
                    libc::setrlimit(resource, &limit);
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{raised, LIMITS};

        /// Each soft limit ends at its target and both signals are ignored.
        /// Run in a child so the test process keeps its own limits; the
        /// child allocates nothing, so its own low limits do not stop it.
        ///
        /// FAILS ON REVERT: with only the file size limit lifted (the first
        /// round), the CPU, data, open file and stack limits stay low and
        /// SIGXCPU stays at its default.
        #[test]
        fn soft_limits_rise_and_the_signals_are_ignored() {
            // SAFETY: fork in a test; the child only makes async-signal-safe
            // calls and _exit.
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork");
            if pid == 0 {
                let mut code = 0;
                unsafe {
                    for (resource, _) in LIMITS {
                        let mut now = libc::rlimit {
                            rlim_cur: 0,
                            rlim_max: 0,
                        };
                        libc::getrlimit(resource, &mut now);
                        let low = libc::rlimit {
                            rlim_cur: now.rlim_max.min(64),
                            rlim_max: now.rlim_max,
                        };
                        libc::setrlimit(resource, &low);
                    }
                    libc::signal(libc::SIGXFSZ, libc::SIG_DFL);
                    libc::signal(libc::SIGXCPU, libc::SIG_DFL);
                    super::lift();
                    for (bit, (resource, most)) in LIMITS.into_iter().enumerate() {
                        let mut now = libc::rlimit {
                            rlim_cur: 0,
                            rlim_max: 0,
                        };
                        libc::getrlimit(resource, &mut now);
                        if now.rlim_cur != most.min(now.rlim_max) {
                            code |= 1 << bit;
                        }
                    }
                    for (bit, signal) in [(6, libc::SIGXFSZ), (7, libc::SIGXCPU)] {
                        if libc::signal(signal, libc::SIG_IGN) != libc::SIG_IGN {
                            code |= 1 << bit;
                        }
                    }
                    libc::_exit(code);
                }
            }
            let mut status = 0;
            // SAFETY: waiting on the child just forked.
            unsafe { libc::waitpid(pid, &mut status, 0) };
            assert!(libc::WIFEXITED(status), "child ended by a signal: {status}");
            assert_eq!(
                libc::WEXITSTATUS(status),
                0,
                "bits: 0 fsize, 1 cpu, 2 as, 3 data, 4 nofile, 5 stack not raised; \
                 6 SIGXFSZ, 7 SIGXCPU not ignored"
            );
        }

        /// A limit already at or past its target is left where it is.
        #[test]
        fn a_limit_is_never_lowered() {
            let inf = libc::RLIM_INFINITY;
            assert_eq!(raised(64, inf, inf), inf);
            assert_eq!(raised(64, 4096, inf), 4096);
            assert_eq!(raised(64, inf, 1024), 1024);
            assert_eq!(raised(64, 512, 1024), 512);
            assert_eq!(raised(65536, inf, 1024), 65536);
            assert_eq!(raised(inf, inf, 1024), inf);
        }
    }
}
