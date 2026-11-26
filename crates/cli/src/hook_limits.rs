//! The file size limit the hook is started with.
//!
//! A process that writes past its soft `RLIMIT_FSIZE` is sent `SIGXFSZ`,
//! and the default action of that signal ends it. A limit lowered on the
//! agent (`prlimit --pid` on its process, `ulimit -f` in the shell that
//! starts it) is inherited by every hook the agent starts, so the first
//! record the hook appends past the limit killed it before it answered:
//! empty stdout and no exit code, which the agent reads as a hook that
//! failed and runs the call unscreened. Measured with release binaries on a
//! disposable home: a refused command and a plain `ls -la` both went out
//! that way.
//!
//! The hook ignores the signal and raises the soft limit to the hard one
//! before it does anything else. A write the hard limit still refuses then
//! fails with an error (`EFBIG`) the writer already handles as a lost
//! record, and the verdict is answered as on any other call. The signal stays
//! ignored in what the hook starts, which then gets the same error instead
//! of dying.

/// Keep a lowered file size limit from killing the hook. Called first thing
/// on the hook's way in; nothing to do off Unix.
pub(crate) fn keep_writes_from_killing_the_hook() {
    #[cfg(unix)]
    unix::lift();
}

#[cfg(unix)]
mod unix {
    pub(super) fn lift() {
        // SAFETY: SIG_IGN is a valid disposition for SIGXFSZ, set before any
        // thread of the hook is started.
        unsafe {
            libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
        }
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is a valid rlimit the call fills.
        if unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut limit) } != 0 {
            return;
        }
        if limit.rlim_cur != limit.rlim_max {
            limit.rlim_cur = limit.rlim_max;
            // SAFETY: a soft limit equal to the hard one is always allowed;
            // a failure leaves the limit as it was and the signal ignored.
            unsafe {
                libc::setrlimit(libc::RLIMIT_FSIZE, &limit);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        /// The soft limit ends at the hard one and the signal is ignored.
        /// Run in a child so the test process keeps its own limit.
        #[test]
        fn soft_limit_rises_to_the_hard_one_and_the_signal_is_ignored() {
            // SAFETY: fork in a test; the child only makes async-signal-safe
            // calls and _exit.
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork");
            if pid == 0 {
                let code = unsafe {
                    let low = libc::rlimit {
                        rlim_cur: 1024,
                        rlim_max: libc::RLIM_INFINITY,
                    };
                    libc::setrlimit(libc::RLIMIT_FSIZE, &low);
                    libc::signal(libc::SIGXFSZ, libc::SIG_DFL);
                    super::lift();
                    let mut now = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    libc::getrlimit(libc::RLIMIT_FSIZE, &mut now);
                    let ignored = libc::signal(libc::SIGXFSZ, libc::SIG_IGN) == libc::SIG_IGN;
                    if now.rlim_cur == libc::RLIM_INFINITY && ignored {
                        0
                    } else {
                        1
                    }
                };
                unsafe { libc::_exit(code) };
            }
            let mut status = 0;
            // SAFETY: waiting on the child just forked.
            unsafe { libc::waitpid(pid, &mut status, 0) };
            assert!(libc::WIFEXITED(status), "child ended by a signal: {status}");
            assert_eq!(
                libc::WEXITSTATUS(status),
                0,
                "limit not raised or signal not ignored"
            );
        }
    }
}
