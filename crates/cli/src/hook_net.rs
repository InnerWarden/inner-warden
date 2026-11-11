//! The net under the hook: a screening that ends without an answer.
//!
//! An agent blocks a tool call only when its hook exits 2. A hook that dies
//! on a signal, or that the agent kills at its own hook timeout, reads as
//! "show stderr, carry on": the call runs, unscreened and unrecorded. The
//! panic guard in `main.rs` covers a panic. This covers the two ends a panic
//! guard never sees.
//!
//! **A fault.** A stack overflow is not a panic: the process ends on a
//! signal. On unix the signals a fault raises get a handler that runs on its
//! own stack (an overflow leaves none to run on), says what happened and
//! exits.
//!
//! **No answer in time.** A line that costs more to read than the agent
//! waits, a caller that never closes stdin, a wait that never ends. A
//! watchdog thread ends the hook at [`DEADLINE`], well inside the wait of the
//! agents this hook is wired to. A wait the hook makes on purpose and bounds
//! itself (the second opinion of a model) moves the deadline by its bound
//! with [`allow_wait`].
//!
//! Both end as a call the hook could not read does: 2 in enforce (the call
//! is refused), 1 in monitor (it never blocks, and says the call went
//! unscreened).
//!
//! Not closed here: `SIGKILL`, which no process can answer, and a fault on
//! Windows, where only the deadline is armed.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// How long the hook has to answer. Reading a line takes milliseconds, and
/// every wait the hook makes on the way is bounded well under a second (the
/// record's locks, the host's answer, a notification), so ten seconds is a
/// hook that is not going to answer. An agent waits 60 s or more for a hook
/// unless its operator set less.
pub const DEADLINE: Duration = Duration::from_secs(10);

/// Lowers [`DEADLINE`], in milliseconds, for an operator whose agent waits
/// less for a hook than the default. It never raises it: a value above the
/// default, zero, or anything that is not a number leaves the default.
pub const DEADLINE_ENV: &str = "INNERWARDEN_HOOK_DEADLINE_MS";

static MONITOR: AtomicBool = AtomicBool::new(false);

/// Milliseconds after [`arm`] at which the watchdog ends the hook. Zero while
/// no deadline is armed.
static DEADLINE_MS: AtomicU64 = AtomicU64::new(0);

const OUT_OF_TIME_ENFORCE: &str =
    "InnerWarden hook: the screening of this tool call did not finish in time; refusing it \
     rather than letting it run unscreened.\n  If the command line is very long, write it \
     shorter, as separate commands, or with the long value in a file.\n";
const OUT_OF_TIME_MONITOR: &str =
    "InnerWarden hook: the screening of this tool call did not finish in time; it was NOT \
     screened (monitor mode never blocks).\n";
#[cfg(unix)]
const FAULT_ENFORCE: &str =
    "InnerWarden hook: a fault stopped the screening of this tool call; refusing it rather \
     than letting it run unscreened.\n";
#[cfg(unix)]
const FAULT_MONITOR: &str =
    "InnerWarden hook: a fault stopped the screening of this tool call; it was NOT screened \
     (monitor mode never blocks).\n";

/// The deadline the hook runs under: [`DEADLINE`], or the lower one the
/// environment names.
fn deadline_from(named: Option<&str>) -> Duration {
    named
        .and_then(|text| text.trim().parse::<u64>().ok())
        .filter(|&ms| ms > 0)
        .map(Duration::from_millis)
        .filter(|&lower| lower < DEADLINE)
        .unwrap_or(DEADLINE)
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Arm the net for this hook run: the fault handlers on the calling thread
/// (the one that screens) and the deadline. An error is a net that could not
/// be set; the caller refuses the call as one it could not read.
pub fn arm(monitor: bool) -> Result<(), &'static str> {
    let named = std::env::var(DEADLINE_ENV).ok();
    arm_with(monitor, deadline_from(named.as_deref()))
}

fn arm_with(monitor: bool, deadline: Duration) -> Result<(), &'static str> {
    MONITOR.store(monitor, Ordering::SeqCst);
    #[cfg(unix)]
    fault::install()?;
    let armed = Instant::now();
    DEADLINE_MS.store(millis(deadline).max(1), Ordering::SeqCst);
    std::thread::Builder::new()
        .name("hook-deadline".into())
        .spawn(move || watch(armed))
        .map(|_| ())
        .map_err(|_| "no screening deadline could be set")
}

/// The hook is about to make a wait it bounds itself by `bound`: move the
/// deadline by as much. Nothing to move when no deadline is armed (the same
/// code runs under `innerwarden check`).
pub fn allow_wait(bound: Duration) {
    let _ = DEADLINE_MS.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |armed| {
        (armed != 0).then(|| armed.saturating_add(millis(bound)))
    });
}

/// Sleep to the deadline, read it again (a wait may have moved it), end the
/// hook once it is behind.
fn watch(armed: Instant) -> ! {
    loop {
        let deadline = Duration::from_millis(DEADLINE_MS.load(Ordering::SeqCst));
        match deadline.checked_sub(armed.elapsed()) {
            Some(left) if !left.is_zero() => std::thread::sleep(left),
            _ => {
                if MONITOR.load(Ordering::SeqCst) {
                    end(OUT_OF_TIME_MONITOR, crate::unreadable_exit_code(true))
                } else {
                    end(OUT_OF_TIME_ENFORCE, crate::unreadable_exit_code(false))
                }
            }
        }
    }
}

/// Say `message` and end the process with `code`, from a thread that is not
/// the one screening, or from a signal handler.
///
/// On unix this is `write` and `_exit` and nothing else: both may be called
/// from a signal handler, neither takes a lock the stopped thread may hold
/// (the lock on stderr), and `_exit` runs no exit handler beside a thread
/// that is still running.
#[cfg(unix)]
fn end(message: &'static str, code: u8) -> ! {
    // SAFETY: `message` is a live buffer of `message.len()` bytes; `write`
    // and `_exit` are async-signal-safe and `_exit` does not return.
    unsafe {
        libc::write(2, message.as_ptr().cast(), message.len());
        libc::_exit(i32::from(code))
    }
}

/// Where there is no `_exit`: say it and end the process.
#[cfg(not(unix))]
fn end(message: &'static str, code: u8) -> ! {
    let _ = std::io::Write::write_all(&mut std::io::stderr(), message.as_bytes());
    std::process::exit(i32::from(code))
}

#[cfg(unix)]
mod fault {
    use std::sync::atomic::Ordering;

    /// What a fault of the process itself raises: an abort (a stack overflow
    /// reported by the runtime, an allocation that failed), a bad access (a
    /// stack overflow, by signal), an illegal or trap instruction (an abort
    /// compiled in line), an arithmetic fault, a refused system call.
    const SIGNALS: [libc::c_int; 7] = [
        libc::SIGABRT,
        libc::SIGSEGV,
        libc::SIGBUS,
        libc::SIGILL,
        libc::SIGFPE,
        libc::SIGTRAP,
        libc::SIGSYS,
    ];

    /// Room for the handler when the thread's own stack is gone.
    const HANDLER_STACK: usize = 1 << 16;

    extern "C" fn on_fault(_signal: libc::c_int) {
        // Only what a signal handler may do: read an atomic, `write`, `_exit`.
        if super::MONITOR.load(Ordering::SeqCst) {
            super::end(super::FAULT_MONITOR, crate::unreadable_exit_code(true))
        } else {
            super::end(super::FAULT_ENFORCE, crate::unreadable_exit_code(false))
        }
    }

    /// Give the calling thread a stack for the handler and point the fault
    /// signals at it.
    pub fn install() -> Result<(), &'static str> {
        const REFUSED: &str = "no fault handler could be set";
        let size = HANDLER_STACK.max(libc::SIGSTKSZ);
        // Never freed: the handler may need it until the process ends.
        let stack = Box::leak(vec![0u8; size].into_boxed_slice());
        let alternate = libc::stack_t {
            ss_sp: stack.as_mut_ptr().cast(),
            ss_flags: 0,
            ss_size: size,
        };
        // SAFETY: `alternate` describes a live, leaked buffer of `size` bytes.
        if unsafe { libc::sigaltstack(&alternate, std::ptr::null_mut()) } != 0 {
            return Err(REFUSED);
        }
        for signal in SIGNALS {
            // SAFETY: a zeroed `sigaction` is a valid value to fill in; the
            // handler has the one-argument signature that the flags (no
            // `SA_SIGINFO`) ask for.
            let installed = unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = on_fault as extern "C" fn(libc::c_int) as usize;
                action.sa_flags = libc::SA_ONSTACK;
                libc::sigemptyset(&mut action.sa_mask);
                libc::sigaction(signal, &action, std::ptr::null_mut())
            };
            if installed != 0 {
                return Err(REFUSED);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    /// The default holds unless the environment names a LOWER bound.
    ///
    /// FAILS ON REVERT: take the named value as it comes and a large one
    /// puts the deadline past the agent's own wait, where it never fires.
    #[test]
    fn the_environment_lowers_the_deadline_and_never_raises_it() {
        assert_eq!(deadline_from(None), DEADLINE);
        assert_eq!(deadline_from(Some("300")), Duration::from_millis(300));
        assert_eq!(deadline_from(Some(" 9999 ")), Duration::from_millis(9999));
        for kept in [
            "10000",
            "600000",
            "0",
            "",
            "abc",
            "-5",
            "1.5",
            "18446744073709551616",
        ] {
            assert_eq!(deadline_from(Some(kept)), DEADLINE, "{kept:?}");
        }
    }

    /// Never returns: each call keeps a frame the next one needs.
    #[allow(unconditional_recursion)]
    fn overflow_the_stack(depth: u64) -> u64 {
        let frame = std::hint::black_box([depth; 64]);
        overflow_the_stack(depth + 1) + frame[0]
    }

    const CHILD: &str = "INNERWARDEN_TEST_HOOK_NET_CHILD";
    /// Far past any end the net gives: a child still alive here was not ended.
    const GIVE_UP: Duration = Duration::from_secs(30);

    /// What the child does once the parent names an end.
    fn act_as_child(test: &str) {
        let Ok(asked) = std::env::var(CHILD) else {
            return;
        };
        let (mode, end) = asked.split_once(':').expect("mode:end");
        let monitor = mode == "monitor";
        match end {
            "overflow" => {
                arm_with(monitor, DEADLINE).expect("arm");
                std::hint::black_box(overflow_the_stack(0));
            }
            "abort" => {
                arm_with(monitor, DEADLINE).expect("arm");
                std::process::abort();
            }
            "stall" => {
                arm_with(monitor, Duration::from_millis(200)).expect("arm");
                loop {
                    std::hint::black_box(0u8);
                }
            }
            "allowed-wait" => {
                arm_with(monitor, Duration::from_millis(200)).expect("arm");
                allow_wait(Duration::from_secs(3));
                loop {
                    std::hint::black_box(0u8);
                }
            }
            other => panic!("{test}: unknown end {other}"),
        }
    }

    /// Run this test again as a child told to end one way; its exit code,
    /// what it said, and how long it took.
    fn child(test: &str, asked: &str) -> (Option<i32>, String, Duration) {
        let started = Instant::now();
        let mut child = Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                &format!("hook_net::tests::{test}"),
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, asked)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run the child");
        let status = loop {
            if let Some(status) = child.try_wait().expect("wait") {
                break status;
            }
            if started.elapsed() > GIVE_UP {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{asked}: the child was still running after {GIVE_UP:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let took = started.elapsed();
        let mut said = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            let _ = std::io::Read::read_to_string(&mut stderr, &mut said);
        }
        (status.code(), said, took)
    }

    /// A stack overflow and an abort while screening refuse the call (2) in
    /// enforce and are loud (1) in monitor. Proven in a child process that
    /// arms the net and then overflows its stack for real, or aborts.
    ///
    /// FAILS ON REVERT: without the handlers, or with a handler that has no
    /// stack of its own, the child ends on a signal and has no exit code.
    #[cfg(unix)]
    #[test]
    fn a_fault_while_screening_refuses_the_call() {
        const TEST: &str = "a_fault_while_screening_refuses_the_call";
        act_as_child(TEST);
        for end in ["overflow", "abort"] {
            for (mode, expected, says) in [
                (
                    "enforce",
                    2,
                    "refusing it rather than letting it run unscreened",
                ),
                ("monitor", 1, "it was NOT screened"),
            ] {
                let (code, said, _) = child(TEST, &format!("{mode}:{end}"));
                assert_eq!(code, Some(expected), "{mode}:{end}: {said}");
                assert!(
                    said.contains("a fault stopped the screening"),
                    "{mode}:{end}: {said}"
                );
                assert!(said.contains(says), "{mode}:{end}: {said}");
            }
        }
    }

    /// A screening still busy at the deadline refuses the call (2) in enforce
    /// and is loud (1) in monitor.
    ///
    /// FAILS ON REVERT: without the watchdog the child spins until this test
    /// gives up on it.
    #[test]
    fn a_screening_past_its_deadline_refuses_the_call() {
        const TEST: &str = "a_screening_past_its_deadline_refuses_the_call";
        act_as_child(TEST);
        for (mode, expected, says) in [
            (
                "enforce",
                2,
                "refusing it rather than letting it run unscreened",
            ),
            ("monitor", 1, "it was NOT screened"),
        ] {
            let (code, said, _) = child(TEST, &format!("{mode}:stall"));
            assert_eq!(code, Some(expected), "{mode}: {said}");
            assert!(said.contains("did not finish in time"), "{mode}: {said}");
            assert!(said.contains(says), "{mode}: {said}");
        }
    }

    /// A wait the hook bounds itself moves the deadline by its bound, and
    /// the call is still refused once that is behind too. With no deadline
    /// armed there is nothing to move.
    ///
    /// FAILS ON REVERT: with `allow_wait` doing nothing the child ends at
    /// its 200 ms and not after the 3 s it was allowed.
    #[test]
    fn a_wait_the_hook_bounds_moves_the_deadline_by_its_bound() {
        const TEST: &str = "a_wait_the_hook_bounds_moves_the_deadline_by_its_bound";
        act_as_child(TEST);
        let (code, said, took) = child(TEST, "enforce:allowed-wait");
        assert_eq!(code, Some(2), "{said}");
        assert!(said.contains("did not finish in time"), "{said}");
        assert!(took >= Duration::from_secs(3), "ended after {took:?}");

        // This process never arms (only the children do): nothing to move.
        allow_wait(Duration::from_secs(3));
        assert_eq!(DEADLINE_MS.load(Ordering::SeqCst), 0);
    }
}
